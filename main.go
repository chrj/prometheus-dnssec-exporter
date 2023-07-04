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
	expiry   *prometheus.GaugeVec

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
		expiry: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "dnssec",
				Subsystem: "zone",
				Name:      "record_earliest_rrsig_expiry",
				Help:      "Earliest expiring RRSIG covering the record on resolver in unixtime",
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
	e.expiry.Describe(ch)
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {

	var wg sync.WaitGroup

	wg.Add(len(e.Records) * (len(e.resolvers)))

	for _, rec := range e.Records {

		rec := rec

		// Check the configured resolvers

		for _, resolver := range e.resolvers {

			resolver := resolver

			go func() {

				resolves, expires := e.resolve(&rec, resolver)

				// AXFR is not a record type.  Don't create bogus
				// metrics for failed zone transfers.
				if (rec.Type == "AXFR") {
					wg.Done()
					return
				}

				e.resolves.WithLabelValues(
					resolver, rec.Zone, rec.Record, rec.Type,
				).Set(map[bool]float64{true: 1}[resolves])

				// Only return the signature expiry if the record resolves.
				if resolves {
					e.expiry.WithLabelValues(
						resolver, rec.Zone, rec.Record, rec.Type,
					).Set(float64(expires.Unix()))
				}

				// For compatibility with historical behaviour, record_days_left
				// returns the time until the earliest RRSIG expiration on the
				// first configured resolver.  This value will be bogus if that
				// resolver fails to resolve and validate the record.
				if (resolver == e.resolvers[0]) {
					e.records.WithLabelValues(
						rec.Zone, rec.Record, rec.Type,
					).Set(float64(time.Until(expires)/time.Hour) / 24)
				}

				wg.Done()

			}()

		}

	}

	wg.Wait()

	e.records.Collect(ch)
	e.resolves.Collect(ch)
	e.expiry.Collect(ch)

}

func (e *Exporter) resolve(record *Records, resolver string) (resolves bool, expires time.Time) {

	msg := &dns.Msg{}
	msg.SetQuestion(hostname(record), dns.StringToType[record.Type])
	msg.SetEdns0(4096, true)

	response, _, err := e.dnsClient.Exchange(msg, resolver)
	if err != nil {
		e.logger.Printf("error resolving %v %v on %v: %v",
			hostname(record), record.Type, resolver, err)
		return
	}

	// AXFR queries can fail in interesting ways.
	if record.Type == "AXFR" && response.Rcode != dns.RcodeSuccess {
		e.logger.Printf("afxr for %v failed on %v: %v",
			hostname(record), resolver, dns.RcodeToString[response.Rcode])
		return
	}

	// Validating recursive resolvers set the AD bit,
	// authoritative resolvers set the AA bit.
	resolves = response.Rcode == dns.RcodeSuccess &&
		response.AuthenticatedData || response.Authoritative

	// If multiple RRSIGs are found, report the one that will expire the earliest.
	for _, rr := range response.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			sigexp := time.Unix(int64(rrsig.Expiration), 0)
			if (expires.IsZero() || sigexp.Before(expires) && !sigexp.IsZero()) {
				record.Record = rrsig.Hdr.Name
				record.Type = dns.TypeToString[rrsig.TypeCovered]
				expires = sigexp;
			}
		}
	}

	return
}

func hostname(record *Records) string {

	if record.Record == "@" {
		return fmt.Sprintf("%s.", record.Zone)
	}

	return fmt.Sprintf("%s.%s.", record.Record, record.Zone)

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

	log.Fatal(http.ListenAndServe(*addr, nil))

}
