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

var dnsClient *dns.Client

type Records struct {
	Zone   string
	Record string
	Type   string
}

type Exporter struct {
	Records []Records

	records *prometheus.GaugeVec
	valid   *prometheus.GaugeVec
}

func NewDNSSECExporter() *Exporter {
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
			e.collectRecord(rec.Zone, rec.Record, rec.Type)
			wg.Done()
		}()

	}

	wg.Wait()

	e.records.Collect(ch)
	e.valid.Collect(ch)

}

func (e *Exporter) collectRecord(zone, record, recordType string) {

	// Start by finding the DNSKEY

	msg := &dns.Msg{}
	msg.SetQuestion(fmt.Sprintf("%s.", zone), dns.TypeDNSKEY)

	response, _, err := dnsClient.Exchange(msg, *resolver)
	if err != nil {
		log.Printf("while looking up DNSKEY for %v: %v", zone, err)
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
		log.Printf("didn't find DNSKEY for %v", zone)
	}

	// Now lookup the signature

	msg = &dns.Msg{}
	msg.SetQuestion(hostname(zone, record), dns.TypeRRSIG)

	response, _, err = dnsClient.Exchange(msg, *resolver)
	if err != nil {
		log.Printf("while looking up RRSIG for %v: %v", hostname(zone, record), err)
		return
	}

	var sig *dns.RRSIG
	var key *dns.DNSKEY

	for _, rr := range response.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {

			if rrsig.TypeCovered == dns.StringToType[recordType] &&
				keys[rrsig.KeyTag] != nil {

				sig = rrsig
				key = keys[rrsig.KeyTag]
				break

			}

		}
	}

	if sig == nil {
		log.Printf("didn't find RRSIG for %v covering type %v", hostname(zone, record), recordType)
		return
	}

	exp := time.Unix(int64(sig.Expiration), 0)
	if exp.IsZero() {
		log.Print("zero exp")
		return
	}

	e.records.WithLabelValues(
		zone, record, recordType,
	).Set(float64(time.Until(exp)/time.Hour) / 24)

	// Finally, lookup the records to validate

	if key == nil {
		e.valid.WithLabelValues(zone, record, recordType).Set(0)
		return
	}

	msg = &dns.Msg{}
	msg.SetQuestion(hostname(zone, record), dns.StringToType[recordType])

	response, _, err = dnsClient.Exchange(msg, *resolver)
	if err != nil {
		log.Printf("while looking up RRSet for %v type %v: %v", hostname(zone, record), recordType, err)
		return
	}

	if err := sig.Verify(key, response.Answer); err == nil {
		e.valid.WithLabelValues(zone, record, recordType).Set(1)
	} else {
		log.Printf("verify error for %v type %v): %v", hostname(zone, record), recordType, err)
		e.valid.WithLabelValues(zone, record, recordType).Set(0)
	}

}

func hostname(zone, record string) string {

	if record == "@" {
		return fmt.Sprintf("%s.", zone)
	}

	return fmt.Sprintf("%s.%s.", record, zone)

}

func main() {

	flag.Parse()

	dnsClient = &dns.Client{
		Net:     "tcp",
		Timeout: *timeout,
	}

	f, err := os.Open(*conf)
	if err != nil {
		log.Fatalf("couldn't open configuration file: %v", err)
	}

	exporter := NewDNSSECExporter()

	if err := toml.NewDecoder(f).Decode(exporter); err != nil {
		log.Fatalf("couldn't parse configuration file: %v", err)
	}

	prometheus.MustRegister(exporter)

	http.Handle("/metrics", promhttp.Handler())

	log.Fatal(http.ListenAndServe(*addr, nil))

}
