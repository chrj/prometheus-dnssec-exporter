package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

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
