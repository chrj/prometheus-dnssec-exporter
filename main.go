package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/naoina/toml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var addr = flag.String("listen-address", ":9204", "Prometheus metrics port")
var conf = flag.String("config", "/etc/dnssec-checks", "Configuration file")
var resolvers = flag.String("resolvers", "8.8.8.8:53,1.1.1.1:53", "Resolvers to use (comma separated)")
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

	records  *prometheus.GaugeVec
	resolves *prometheus.GaugeVec

	resolvers []string
	dnsClient *dns.Client

	logger Logger
}

func NewDNSSECExporter(timeout time.Duration, resolvers []string, logger Logger) *Exporter {
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
		resolves: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "dnssec",
				Subsystem: "zone",
				Name:      "record_resolves",
				Help:      "Does the record resolve using the specified DNSSEC enabled resolvers",
			},
			[]string{
				"resolver",
				"zone",
				"record",
				"type",
			},
		),
		dnsClient: &dns.Client{
			Net:     "tcp",
			Timeout: timeout,
		},
		resolvers: resolvers,
		logger:    logger,
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.records.Describe(ch)
	e.resolves.Describe(ch)
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {

	var wg sync.WaitGroup

	wg.Add(len(e.Records) * (len(e.resolvers) + 1))

	for _, rec := range e.Records {

		rec := rec

		// Check the expiration

		go func() {

			exp := e.expiration(rec.Zone, rec.Record, rec.Type)

			e.records.WithLabelValues(
				rec.Zone, rec.Record, rec.Type,
			).Set(float64(time.Until(exp)/time.Hour) / 24)

			wg.Done()

		}()

		// Check the configured resolvers

		for _, resolver := range e.resolvers {

			resolver := resolver

			go func() {

				resolves := e.resolve(rec.Zone, rec.Record, rec.Type, resolver)

				e.resolves.WithLabelValues(
					resolver, rec.Zone, rec.Record, rec.Type,
				).Set(map[bool]float64{true: 1}[resolves])

				wg.Done()

			}()

		}

	}

	wg.Wait()

	e.records.Collect(ch)
	e.resolves.Collect(ch)

}

func (e *Exporter) expiration(zone, record, recordType string) (exp time.Time) {

	msg := &dns.Msg{}
	msg.SetQuestion(hostname(zone, record), dns.TypeRRSIG)

	response, _, err := e.dnsClient.Exchange(msg, e.resolvers[0])
	if err != nil {
		e.logger.Printf("while looking up RRSIG for %v: %v", hostname(zone, record), err)
		return
	}

	var sig *dns.RRSIG

	for _, rr := range response.Answer {

		if rrsig, ok := rr.(*dns.RRSIG); ok &&
			rrsig.TypeCovered == dns.StringToType[recordType] {

			sig = rrsig
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

	return

}

func (e *Exporter) resolve(zone, record, recordType, resolver string) (resolves bool) {

	msg := &dns.Msg{}
	msg.SetQuestion(hostname(zone, record), dns.StringToType[recordType])
	msg.SetEdns0(4096, true)

	response, _, err := e.dnsClient.Exchange(msg, resolver)
	if err != nil {
		e.logger.Printf("while resolving for %v: %v", hostname(zone, record), err)
		return
	}

	return response.AuthenticatedData &&
		!response.CheckingDisabled &&
		response.Rcode == dns.RcodeSuccess

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

	r := strings.Split(*resolvers, ",")

	exporter := NewDNSSECExporter(*timeout, r, logger)

	if err := toml.NewDecoder(f).Decode(exporter); err != nil {
		log.Fatalf("couldn't parse configuration file: %v", err)
	}

	prometheus.MustRegister(exporter)

	http.Handle("/metrics", promhttp.Handler())
        http.HandleFunc("/-/healthy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Healthy"))
	})
	log.Fatal(http.ListenAndServe(*addr, nil))

}
