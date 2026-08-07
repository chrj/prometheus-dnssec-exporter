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
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
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

// tsigFudge is the time difference in seconds that a TSIG signature tolerates
// between the two clocks. 300 is the value that BIND and Knot use.
const tsigFudge = 300

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

// Zone is one entry from the [[zones]] table. The exporter transfers the whole
// zone and reports the record whose signature expires first.
type Zone struct {
	Zone   string
	Server string
	Key    string
}

// Key is one entry from the [[keys]] table. It is a TSIG key that authenticates
// a zone transfer.
type Key struct {
	Name      string
	Algorithm string
	Secret    string
}

// LogValue keeps the secret out of the logs. Without it, a log call that takes
// the whole key writes the shared secret to the log file.
func (k Key) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", k.Name),
		slog.String("algorithm", k.Algorithm),
	)
}

// String keeps the secret out of error messages, for the same reason.
func (k Key) String() string {
	return fmt.Sprintf("%s (%s)", k.Name, k.Algorithm)
}

// Exporter collects DNSSEC signature data at scrape time. It holds no metric
// state between scrapes, so a failed query makes the affected series absent
// instead of leaving a stale value behind.
type Exporter struct {
	Records []Record
	Zones   []Zone
	Keys    []Key

	daysLeft  *prometheus.Desc
	resolves  *prometheus.Desc
	expiry    *prometheus.Desc
	transfers *prometheus.Desc

	// keys indexes Keys by name, so a zone can name the key it needs.
	keys map[string]Key

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
		transfers: prometheus.NewDesc(
			"dnssec_zone_transfer_success",
			"Did the zone transfer from the configured server succeed",
			[]string{"server", "zone"},
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
	if len(e.Records) == 0 && len(e.Zones) == 0 {
		return errors.New("nothing configured to check: add at least one [[records]] or [[zones]] section")
	}

	if err := e.validateKeys(); err != nil {
		return err
	}

	if err := e.validateZones(); err != nil {
		return err
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

// validateKeys checks the [[keys]] table and indexes it by key name.
func (e *Exporter) validateKeys() error {
	e.keys = make(map[string]Key, len(e.Keys))

	for _, key := range e.Keys {
		if key.Name == "" {
			return errors.New("a key has no name: give every [[keys]] entry a name")
		}

		if key.Secret == "" {
			return fmt.Errorf("key %s has no secret: give it the base64 secret from tsig-keygen", key.Name)
		}

		// miekg/dns matches the key name and algorithm in canonical form, so a
		// name written without the trailing dot never matches the answer.
		name := dns.Fqdn(key.Name)
		algorithm := dns.Fqdn(key.Algorithm)

		if !tsigAlgorithms[algorithm] {
			return fmt.Errorf("key %s has unknown algorithm %q, use one of %s",
				key.Name, key.Algorithm, strings.Join(tsigAlgorithmNames(), ", "))
		}

		if _, ok := e.keys[name]; ok {
			return fmt.Errorf("key %s is configured more than once, remove the duplicate", key.Name)
		}

		e.keys[name] = Key{Name: name, Algorithm: algorithm, Secret: key.Secret}
	}

	return nil
}

// validateZones checks the [[zones]] table against the configured keys.
func (e *Exporter) validateZones() error {
	seen := make(map[string]bool, len(e.Zones))

	for _, zone := range e.Zones {
		if zone.Zone == "" {
			return errors.New("a zone has no name: give every [[zones]] entry a zone")
		}

		if zone.Key != "" {
			if _, ok := e.keys[dns.Fqdn(zone.Key)]; !ok {
				return fmt.Errorf("zone %s uses key %q, which no [[keys]] section defines", zone.Zone, zone.Key)
			}
		}

		if zone.Server != "" {
			if _, _, err := net.SplitHostPort(zone.Server); err != nil {
				return fmt.Errorf("zone %s: server %q needs a port, for example %q",
					zone.Zone, zone.Server, net.JoinHostPort(zone.Server, defaultDNSPort))
			}
		}

		name := dns.Fqdn(zone.Zone)
		if seen[name] {
			return fmt.Errorf("zone %s is configured more than once, remove the duplicate", zone.Zone)
		}

		seen[name] = true
	}

	return nil
}

// tsigAlgorithms are the TSIG algorithms that miekg/dns still supports. HMAC-MD5
// is left out on purpose, because it is broken and the library rejects it.
var tsigAlgorithms = map[string]bool{
	dns.HmacSHA1:   true,
	dns.HmacSHA224: true,
	dns.HmacSHA256: true,
	dns.HmacSHA384: true,
	dns.HmacSHA512: true,
}

func tsigAlgorithmNames() []string {
	names := make([]string, 0, len(tsigAlgorithms))
	for name := range tsigAlgorithms {
		names = append(names, name)
	}

	slices.Sort(names)

	return names
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.daysLeft
	ch <- e.resolves
	ch <- e.expiry
	ch <- e.transfers
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

	for _, zone := range e.Zones {
		wg.Go(func() {
			e.collectZone(ctx, ch, zone)
		})
	}

	wg.Wait()
}

// collectZone transfers a zone and reports the record that expires first.
func (e *Exporter) collectZone(ctx context.Context, ch chan<- prometheus.Metric, zone Zone) {
	server := zone.Server
	if server == "" {
		server = e.resolvers[0]
	}

	earliest, err := e.transfer(ctx, zone, server)

	var success float64
	if err == nil {
		success = 1
	} else {
		e.logger.Error("zone transfer failed",
			"zone", zone.Zone,
			"server", server,
			"error", err,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		e.transfers, prometheus.GaugeValue, success,
		server, zone.Zone,
	)

	// A zone with no signed record has nothing to report. Leave the signature
	// metrics absent rather than reporting a value that was never measured.
	if err != nil || earliest.expires.IsZero() {
		return
	}

	ch <- prometheus.MustNewConstMetric(
		e.expiry, prometheus.GaugeValue, float64(earliest.expires.Unix()),
		server, zone.Zone, earliest.record, earliest.recordType,
	)

	ch <- prometheus.MustNewConstMetric(
		e.daysLeft, prometheus.GaugeValue, time.Until(earliest.expires).Hours()/24,
		zone.Zone, earliest.record, earliest.recordType,
	)
}

// signature is the RRSIG in a zone that expires first, and the record it covers.
type signature struct {
	record     string
	recordType string
	expires    time.Time
}

// transfer reads a whole zone over AXFR and returns the signature that expires
// first. The caller decides what an error means for the metrics.
func (e *Exporter) transfer(ctx context.Context, zone Zone, server string) (signature, error) {
	var earliest signature

	msg := &dns.Msg{}
	msg.SetAxfr(dns.Fqdn(zone.Zone))

	tr := &dns.Transfer{
		DialTimeout:  e.timeout,
		ReadTimeout:  e.timeout,
		WriteTimeout: e.timeout,
	}

	if zone.Key != "" {
		key := e.keys[dns.Fqdn(zone.Key)]

		tr.TsigSecret = map[string]string{key.Name: key.Secret}
		msg.SetTsig(key.Name, key.Algorithm, tsigFudge, time.Now().Unix())
	}

	envelopes, err := tr.In(msg, server)
	if err != nil {
		return earliest, fmt.Errorf("start transfer: %w", err)
	}

	// The channel must be drained to the end, or the reading goroutine inside
	// the library never stops. Record the first error and keep reading.
	var transferErr error

	for envelope := range envelopes {
		if envelope.Error != nil {
			if transferErr == nil {
				transferErr = envelope.Error
			}

			continue
		}

		if ctx.Err() != nil {
			if transferErr == nil {
				transferErr = ctx.Err()
			}

			continue
		}

		for _, rr := range envelope.RR {
			rrsig, ok := rr.(*dns.RRSIG)
			if !ok {
				continue
			}

			expires := time.Unix(int64(rrsig.Expiration), 0)
			if !earliest.expires.IsZero() && !expires.Before(earliest.expires) {
				continue
			}

			earliest = signature{
				record:     rrsig.Hdr.Name,
				recordType: dns.TypeToString[rrsig.TypeCovered],
				expires:    expires,
			}
		}
	}

	if transferErr != nil {
		return signature{}, fmt.Errorf("read zone: %w", transferErr)
	}

	return earliest, nil
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

	// Without an RRSIG there is nothing to measure, so leave both signature
	// metrics absent rather than reporting a value derived from the zero time.
	if expires.IsZero() {
		return
	}

	// Authoritative servers serve RRSIGs but never set the AD bit, because they
	// do not validate. Report the expiry whenever the response carried an RRSIG
	// so those servers can be monitored too.
	ch <- prometheus.MustNewConstMetric(
		e.expiry, prometheus.GaugeValue, float64(expires.Unix()),
		resolver, rec.Zone, rec.Record, rec.Type,
	)

	// For compatibility with historical behaviour, record_days_left reports the
	// time until the earliest RRSIG expiration on the first configured resolver.
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

// config is the schema of the configuration file.
type config struct {
	Records []Record
	Zones   []Zone
	Keys    []Key
}

// loadExporter reads the configuration file and returns a validated exporter.
func loadExporter(path string, timeout time.Duration, resolvers []string, logger *slog.Logger) (*Exporter, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configuration file %s: %w", path, err)
	}
	// The file is only read, so a failure to close it cannot lose data.
	defer func() { _ = f.Close() }()

	var cfg config

	md, err := toml.NewDecoder(f).Decode(&cfg)
	if err != nil {
		return nil, fmt.Errorf("parse configuration file %s: %w", path, err)
	}

	// A misspelled key must stop the exporter. Left unreported, it reads as a
	// setting that was accepted, while the record is silently not checked.
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}

		return nil, fmt.Errorf("configuration file %s has unknown keys: %s", path, strings.Join(keys, ", "))
	}

	exporter := NewDNSSECExporter(timeout, resolvers, logger)
	exporter.Records = cfg.Records
	exporter.Zones = cfg.Zones
	exporter.Keys = cfg.Keys

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
