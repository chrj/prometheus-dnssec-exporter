package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/naoina/toml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var addr = flag.String("listen-address", ":9204", "Prometheus metrics port")
var conf = flag.String("config", "/etc/dnssec-checks", "Configuration file")
var resolver = flag.String("resolver", "8.8.8.8:53", "Resolver to use")
var timeout = flag.Duration("timeout", 10*time.Second, "Timeout for network operations")

type Records struct {
	Zone   string
	Record string
	Type   string
}

type Logger interface {
	Print(v ...interface{})
	Printf(format string, v ...interface{})
}

type Exporter struct {
	Records []Records

	records *prometheus.GaugeVec
	valid   *prometheus.GaugeVec

	resolver  string
	dnsClient *dns.Client

	logger Logger
}

func NewDNSSECExporter(dnsClient *dns.Client, resolver string, logger Logger) *Exporter {
	return &Exporter{
		records: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "dnssec",
				Subsystem: "zone",
				Name:      "record_days_left",
				Help:      "Number of days the signature will be valid",
			},
			[]string{
				"zone",
				"record",
				"type",
			},
		),
		valid: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "dnssec",
				Subsystem: "zone",
				Name:      "record_valid",
				Help:      "Does this record pass DNSSEC validation",
			},
			[]string{
				"zone",
				"record",
				"type",
			},
		),
		dnsClient: dnsClient,
		resolver:  resolver,
		logger:    logger,
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.records.Describe(ch)
	e.valid.Describe(ch)
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {

	var wg sync.WaitGroup

	wg.Add(len(e.Records))

	for _, rec := range e.Records {

		rec := rec

		go func() {

			valid, exp := e.collectRecord(rec.Zone, rec.Record, rec.Type)

			e.valid.WithLabelValues(
				rec.Zone, rec.Record, rec.Type,
			).Set(map[bool]float64{true: 1}[valid])

			e.records.WithLabelValues(
				rec.Zone, rec.Record, rec.Type,
			).Set(float64(time.Until(exp)/time.Hour) / 24)

			wg.Done()
		}()

	}

	wg.Wait()

	e.records.Collect(ch)
	e.valid.Collect(ch)

}

func (e *Exporter) collectRecord(zone, record, recordType string) (valid bool, exp time.Time) {

	// Start by finding the DNSKEY

	msg := &dns.Msg{}
	msg.SetQuestion(fmt.Sprintf("%s.", zone), dns.TypeDNSKEY)

	response, _, err := e.dnsClient.Exchange(msg, e.resolver)
	if err != nil {
		e.logger.Printf("while looking up DNSKEY for %v: %v", zone, err)
		return
	}

	// Found keys are mapped by tag -> key
	keys := make(map[uint16]*dns.DNSKEY)

	for _, rr := range response.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok && dnskey.Flags&dns.ZONE != 0 {
			keys[dnskey.KeyTag()] = dnskey
		}
	}

	if len(keys) == 0 {
		e.logger.Printf("didn't find DNSKEY for %v", zone)
	}

	// Now lookup the signature

	msg = &dns.Msg{}
	msg.SetQuestion(hostname(zone, record), dns.TypeRRSIG)

	response, _, err = e.dnsClient.Exchange(msg, e.resolver)
	if err != nil {
		e.logger.Printf("while looking up RRSIG for %v: %v", hostname(zone, record), err)
		return
	}

	var sig *dns.RRSIG
	var key *dns.DNSKEY

	for _, rr := range response.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok &&
			rrsig.TypeCovered == dns.StringToType[recordType] &&
			keys[rrsig.KeyTag] != nil {

			sig = rrsig
			key = keys[rrsig.KeyTag]
			break

		}
	}

	if sig == nil {
		e.logger.Printf("didn't find RRSIG for %v covering type %v matching a tag of a DNSKEY", hostname(zone, record), recordType)
		return
	}

	exp = time.Unix(int64(sig.Expiration), 0)
	if exp.IsZero() {
		e.logger.Printf("zero exp for RRSIG for %v covering type %v", hostname(zone, record), recordType)
		return
	}

	// Finally, lookup the records to validate

	if key == nil {
		e.valid.WithLabelValues(zone, record, recordType).Set(0)
		return
	}

	msg = &dns.Msg{}
	msg.SetQuestion(hostname(zone, record), dns.StringToType[recordType])

	response, _, err = e.dnsClient.Exchange(msg, e.resolver)
	if err != nil {
		e.logger.Printf("while looking up RRSet for %v type %v: %v", hostname(zone, record), recordType, err)
		return
	}

	if err := sig.Verify(key, response.Answer); err == nil {
		valid = true
	} else {
		e.logger.Printf("verify error for %v type %v): %v", hostname(zone, record), recordType, err)
	}

	return

}

func hostname(zone, record string) string {

	if record == "@" {
		return fmt.Sprintf("%s.", zone)
	}

	return fmt.Sprintf("%s.%s.", record, zone)

}

func main() {

	flag.Parse()

	f, err := os.Open(*conf)
	if err != nil {
		log.Fatalf("couldn't open configuration file: %v", err)
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)

	exporter := NewDNSSECExporter(&dns.Client{
		Net:     "tcp",
		Timeout: *timeout,
	}, *resolver, logger)

	if err := toml.NewDecoder(f).Decode(exporter); err != nil {
		log.Fatalf("couldn't parse configuration file: %v", err)
	}

	prometheus.MustRegister(exporter)

	http.Handle("/metrics", promhttp.Handler())

	log.Fatal(http.ListenAndServe(*addr, nil))

}
