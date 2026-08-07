// Command prometheus-dnssec-exporter checks DNSSEC signatures for configured
// records and exposes their validity and expiration as Prometheus metrics.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/naoina/toml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// defaultDNSPort is applied to resolvers that are configured without a port.
const defaultDNSPort = "53"

// shutdownTimeout is how long in-flight scrapes get to finish after a signal.
const shutdownTimeout = 10 * time.Second

// readHeaderTimeout bounds how long a client can take to send its headers.
const readHeaderTimeout = 10 * time.Second

// Record is one entry from the configuration file.
type Record struct {
	Zone   string
	Record string
	Type   string
}

// String returns the record in a form that identifies it in logs and errors.
func (r Record) String() string {
	return fmt.Sprintf("%s %s in %s", r.Record, r.Type, r.Zone)
}

// Exporter collects DNSSEC signature data at scrape time. It holds no metric
// state between scrapes, so a failed query makes the affected series absent
// instead of leaving a stale value behind.
type Exporter struct {
	Records []Record

	daysLeft *prometheus.Desc
	resolves *prometheus.Desc
	expiry   *prometheus.Desc

	resolvers []string
	dnsClient *dns.Client
	timeout   time.Duration

	logger *slog.Logger
}

var _ prometheus.Collector = (*Exporter)(nil)

func NewDNSSECExporter(timeout time.Duration, resolvers []string, logger *slog.Logger) *Exporter {
	return &Exporter{
		daysLeft: prometheus.NewDesc(
			"dnssec_zone_record_days_left",
			"Number of days the signature will be valid",
			[]string{"zone", "record", "type"},
			nil,
		),
		resolves: prometheus.NewDesc(
			"dnssec_zone_record_resolves",
			"Does the record resolve using the specified DNSSEC enabled resolvers",
			[]string{"resolver", "zone", "record", "type"},
			nil,
		),
		expiry: prometheus.NewDesc(
			"dnssec_zone_record_earliest_rrsig_expiry",
			"Earliest expiring RRSIG covering the record on resolver in unixtime",
			[]string{"resolver", "zone", "record", "type"},
			nil,
		),
		dnsClient: &dns.Client{
			Net:     "tcp",
			Timeout: timeout,
		},
		resolvers: resolvers,
		timeout:   timeout,
		logger:    logger,
	}
}

// Validate reports configuration problems that would otherwise show up as
// missing or duplicated metrics at scrape time.
func (e *Exporter) Validate() error {
	if len(e.Records) == 0 {
		return errors.New("no records configured: add at least one [[records]] section")
	}

	seen := make(map[Record]bool, len(e.Records))

	for _, rec := range e.Records {
		if rec.Zone == "" {
			return fmt.Errorf("record %q: zone is required", rec.Record)
		}

		if rec.Record == "" {
			return fmt.Errorf("zone %q: record is required, use \"@\" for the zone apex", rec.Zone)
		}

		if _, ok := dns.StringToType[rec.Type]; !ok {
			return fmt.Errorf("record %s in zone %s: unknown type %q, use a DNS type such as SOA, A or MX", rec.Record, rec.Zone, rec.Type)
		}

		if seen[rec] {
			return fmt.Errorf("record %s is configured more than once, remove the duplicate", rec)
		}

		seen[rec] = true
	}

	return nil
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.daysLeft
	ch <- e.resolves
	ch <- e.expiry
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	var wg sync.WaitGroup

	for _, rec := range e.Records {
		for _, resolver := range e.resolvers {
			wg.Go(func() {
				e.collectRecord(ctx, ch, rec, resolver)
			})
		}
	}

	wg.Wait()
}

func (e *Exporter) collectRecord(ctx context.Context, ch chan<- prometheus.Metric, rec Record, resolver string) {
	resolves, expires := e.resolve(ctx, rec, resolver)

	var resolvesValue float64
	if resolves {
		resolvesValue = 1
	}

	ch <- prometheus.MustNewConstMetric(
		e.resolves, prometheus.GaugeValue, resolvesValue,
		resolver, rec.Zone, rec.Record, rec.Type,
	)

	// Only report the signature expiry if the record resolves.
	if resolves {
		ch <- prometheus.MustNewConstMetric(
			e.expiry, prometheus.GaugeValue, float64(expires.Unix()),
			resolver, rec.Zone, rec.Record, rec.Type,
		)
	}

	// For compatibility with historical behaviour, record_days_left reports the
	// time until the earliest RRSIG expiration on the first configured resolver.
	// This value is bogus if that resolver fails to resolve and validate.
	if resolver == e.resolvers[0] {
		ch <- prometheus.MustNewConstMetric(
			e.daysLeft, prometheus.GaugeValue, time.Until(expires).Hours()/24,
			rec.Zone, rec.Record, rec.Type,
		)
	}
}

func (e *Exporter) resolve(ctx context.Context, rec Record, resolver string) (resolves bool, expires time.Time) {
	name := hostname(rec.Zone, rec.Record)

	msg := &dns.Msg{}
	msg.SetQuestion(name, dns.StringToType[rec.Type])
	msg.SetEdns0(4096, true)

	response, _, err := e.dnsClient.ExchangeContext(ctx, msg, resolver)
	if err != nil {
		e.logger.Error("resolving record failed",
			"name", name,
			"type", rec.Type,
			"zone", rec.Zone,
			"resolver", resolver,
			"error", err,
		)
		return
	}

	resolves = response.AuthenticatedData &&
		!response.CheckingDisabled &&
		response.Rcode == dns.RcodeSuccess

	// If multiple RRSIGs cover our record, return the one that expires earliest.
	for _, rr := range response.Answer {
		rrsig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}

		sigexp := time.Unix(int64(rrsig.Expiration), 0)
		if expires.IsZero() || sigexp.Before(expires) {
			expires = sigexp
		}
	}

	return
}

func hostname(zone, record string) string {
	if record == "@" {
		return dns.Fqdn(zone)
	}

	return dns.Fqdn(record + "." + zone)
}

// parseResolvers splits a comma separated resolver list and applies the default
// DNS port to entries that do not carry one.
func parseResolvers(list string) ([]string, error) {
	var resolvers []string

	for entry := range strings.SplitSeq(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if _, _, err := net.SplitHostPort(entry); err != nil {
			entry = net.JoinHostPort(entry, defaultDNSPort)
		}

		resolvers = append(resolvers, entry)
	}

	if len(resolvers) == 0 {
		return nil, errors.New("no resolvers configured: pass at least one address to -resolvers")
	}

	return resolvers, nil
}

// loadExporter reads the configuration file and returns a validated exporter.
func loadExporter(path string, timeout time.Duration, resolvers []string, logger *slog.Logger) (*Exporter, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configuration file %s: %w", path, err)
	}
	// The file is only read, so a failure to close it cannot lose data.
	defer func() { _ = f.Close() }()

	exporter := NewDNSSECExporter(timeout, resolvers, logger)

	if err := toml.NewDecoder(f).Decode(exporter); err != nil {
		return nil, fmt.Errorf("parse configuration file %s: %w", path, err)
	}

	if err := exporter.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration file %s: %w", path, err)
	}

	return exporter, nil
}

func run(ctx context.Context, logger *slog.Logger) error {
	addr := flag.String("listen-address", ":9204", "Prometheus metrics port")
	conf := flag.String("config", "/etc/dnssec-checks", "Configuration file")
	resolvers := flag.String("resolvers", "8.8.8.8:53,1.1.1.1:53", "Resolvers to use (comma separated)")
	timeout := flag.Duration("timeout", 10*time.Second, "Timeout for network operations")

	flag.Parse()

	r, err := parseResolvers(*resolvers)
	if err != nil {
		return err
	}

	exporter, err := loadExporter(*conf, *timeout, r, logger)
	if err != nil {
		return err
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		exporter,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	// Buffered so the goroutine can always report and exit, even after shutdown.
	serveErr := make(chan error, 1)

	go func() {
		logger.Info("listening", "address", *addr, "records", len(exporter.Records), "resolvers", r)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve on %s: %w", *addr, err)
		}
		return nil

	case <-ctx.Done():
		logger.Info("shutting down", "timeout", shutdownTimeout)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down server: %w", err)
		}

		return nil
	}
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err := run(ctx, logger)
	stop()

	if err != nil {
		logger.Error("exporter failed", "error", err)
		os.Exit(1)
	}
}
