package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// Chain is one entry from the [[chains]] table. The exporter follows the chain
// of trust from the DS records at the parent to the keys and signatures on each
// of the zone's authoritative servers, without asking a recursive resolver.
type Chain struct {
	Zone          string
	ParentServers []string `toml:"parent_servers"`
	Servers       []string
}

// chainMetrics are the descriptors for the [[chains]] checks.
type chainMetrics struct {
	querySuccess  *prometheus.Desc
	dsRecords     *prometheus.Desc
	dnskeyRecords *prometheus.Desc
	dsMatch       *prometheus.Desc
	soaValid      *prometheus.Desc
	expiry        *prometheus.Desc
}

func newChainMetrics() chainMetrics {
	return chainMetrics{
		querySuccess: prometheus.NewDesc(
			"dnssec_chain_query_success",
			"Did the server answer the queries for the chain check",
			[]string{"server", "zone"},
			nil,
		),
		dsRecords: prometheus.NewDesc(
			"dnssec_chain_ds_records",
			"Number of DS records for the zone at the parent",
			[]string{"zone"},
			nil,
		),
		dnskeyRecords: prometheus.NewDesc(
			"dnssec_chain_dnskey_records",
			"Number of DNSKEY records the server publishes for the zone",
			[]string{"server", "zone"},
			nil,
		),
		dsMatch: prometheus.NewDesc(
			"dnssec_chain_ds_match",
			"Does a DS record at the parent match a DNSKEY on the server that validly signs the DNSKEY RRset",
			[]string{"server", "zone"},
			nil,
		),
		soaValid: prometheus.NewDesc(
			"dnssec_chain_soa_signature_valid",
			"Does the SOA on the server carry a valid RRSIG from one of the server's DNSKEYs",
			[]string{"server", "zone"},
			nil,
		),
		expiry: prometheus.NewDesc(
			"dnssec_chain_earliest_rrsig_expiry",
			"Earliest expiring RRSIG over the DNSKEY and SOA RRsets on the server in unixtime",
			[]string{"server", "zone"},
			nil,
		),
	}
}

func (m chainMetrics) describe(ch chan<- *prometheus.Desc) {
	ch <- m.querySuccess
	ch <- m.dsRecords
	ch <- m.dnskeyRecords
	ch <- m.dsMatch
	ch <- m.soaValid
	ch <- m.expiry
}

// validateChains checks the [[chains]] table.
func (e *Exporter) validateChains() error {
	seen := make(map[string]bool, len(e.Chains))

	for _, chain := range e.Chains {
		if chain.Zone == "" {
			return errors.New("a chain has no zone: give every [[chains]] entry a zone")
		}

		if len(chain.ParentServers) == 0 {
			return fmt.Errorf("chain %s: parent_servers is required, list the authoritative servers of the parent zone", chain.Zone)
		}

		if len(chain.Servers) == 0 {
			return fmt.Errorf("chain %s: servers is required, list the authoritative servers of the zone", chain.Zone)
		}

		for _, server := range append(append([]string{}, chain.ParentServers...), chain.Servers...) {
			if _, _, err := net.SplitHostPort(server); err != nil {
				return fmt.Errorf("chain %s: server %q needs a port, for example %q",
					chain.Zone, server, net.JoinHostPort(server, defaultDNSPort))
			}
		}

		name := dns.Fqdn(chain.Zone)
		if seen[name] {
			return fmt.Errorf("chain %s is configured more than once, remove the duplicate", chain.Zone)
		}

		seen[name] = true
	}

	return nil
}

// queryAuthoritative asks a server directly, without recursion, and returns the
// records of the requested type and the RRSIGs that cover them.
func (e *Exporter) queryAuthoritative(ctx context.Context, server, name string, qtype uint16) ([]dns.RR, []*dns.RRSIG, error) {
	msg := &dns.Msg{}
	msg.SetQuestion(name, qtype)
	msg.RecursionDesired = false
	msg.SetEdns0(4096, true)

	response, _, err := e.dnsClient.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, nil, err
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("%s %s: %s", name, dns.TypeToString[qtype], dns.RcodeToString[response.Rcode])
	}

	var (
		records []dns.RR
		sigs    []*dns.RRSIG
	)

	for _, rr := range response.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if sig.TypeCovered == qtype {
				sigs = append(sigs, sig)
			}

			continue
		}

		if rr.Header().Rrtype == qtype && strings.EqualFold(rr.Header().Name, name) {
			records = append(records, rr)
		}
	}

	return records, sigs, nil
}

// collectChain checks one [[chains]] entry.
func (e *Exporter) collectChain(ctx context.Context, ch chan<- prometheus.Metric, chain Chain) {
	zone := dns.Fqdn(chain.Zone)

	ds, dsKnown := e.parentDS(ctx, ch, chain, zone)
	if dsKnown {
		ch <- prometheus.MustNewConstMetric(
			e.chain.dsRecords, prometheus.GaugeValue, float64(len(ds)),
			chain.Zone,
		)
	}

	var wg sync.WaitGroup

	for _, server := range chain.Servers {
		wg.Go(func() {
			e.collectChainServer(ctx, ch, chain, zone, server, ds, dsKnown)
		})
	}

	wg.Wait()
}

// parentDS asks every parent server for the DS records and returns the answer
// of the first one that replied. Each parent server reports its own success, so
// a single unreachable server does not hide behind the others.
func (e *Exporter) parentDS(ctx context.Context, ch chan<- prometheus.Metric, chain Chain, zone string) ([]*dns.DS, bool) {
	var (
		ds    []*dns.DS
		known bool
	)

	for _, server := range chain.ParentServers {
		records, _, err := e.queryAuthoritative(ctx, server, zone, dns.TypeDS)

		var success float64
		if err == nil {
			success = 1
		} else {
			e.logger.Error("querying DS at the parent failed",
				"zone", chain.Zone,
				"server", server,
				"error", err,
			)
		}

		ch <- prometheus.MustNewConstMetric(
			e.chain.querySuccess, prometheus.GaugeValue, success,
			server, chain.Zone,
		)

		if err != nil || known {
			continue
		}

		for _, rr := range records {
			if d, ok := rr.(*dns.DS); ok {
				ds = append(ds, d)
			}
		}

		known = true
	}

	return ds, known
}

// collectChainServer checks the keys and signatures that one authoritative
// server of the zone publishes.
func (e *Exporter) collectChainServer(ctx context.Context, ch chan<- prometheus.Metric, chain Chain, zone, server string, ds []*dns.DS, dsKnown bool) {
	keyRecords, keySigs, keyErr := e.queryAuthoritative(ctx, server, zone, dns.TypeDNSKEY)
	soaRecords, soaSigs, soaErr := e.queryAuthoritative(ctx, server, zone, dns.TypeSOA)

	err := errors.Join(keyErr, soaErr)

	var success float64
	if err == nil {
		success = 1
	} else {
		e.logger.Error("querying the zone's server failed",
			"zone", chain.Zone,
			"server", server,
			"error", err,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		e.chain.querySuccess, prometheus.GaugeValue, success,
		server, chain.Zone,
	)

	// Without both answers nothing can be judged. Leave the other metrics
	// absent rather than reporting a failure that was never measured.
	if err != nil {
		return
	}

	keys := make([]*dns.DNSKEY, 0, len(keyRecords))
	for _, rr := range keyRecords {
		if key, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, key)
		}
	}

	ch <- prometheus.MustNewConstMetric(
		e.chain.dnskeyRecords, prometheus.GaugeValue, float64(len(keys)),
		server, chain.Zone,
	)

	now := time.Now()

	// Without a DS answer from any parent server there is nothing to compare
	// against, so the match is unknown rather than false.
	if dsKnown {
		ch <- prometheus.MustNewConstMetric(
			e.chain.dsMatch, prometheus.GaugeValue, boolValue(anchored(zone, ds, keys, keyRecords, keySigs, now)),
			server, chain.Zone,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		e.chain.soaValid, prometheus.GaugeValue, boolValue(signedByAny(zone, soaRecords, soaSigs, keys, now)),
		server, chain.Zone,
	)

	var earliest time.Time

	for _, sig := range append(append([]*dns.RRSIG{}, keySigs...), soaSigs...) {
		expires := time.Unix(int64(sig.Expiration), 0)
		if earliest.IsZero() || expires.Before(earliest) {
			earliest = expires
		}
	}

	if !earliest.IsZero() {
		ch <- prometheus.MustNewConstMetric(
			e.chain.expiry, prometheus.GaugeValue, float64(earliest.Unix()),
			server, chain.Zone,
		)
	}
}

// anchored reports whether a DS record from the parent matches a DNSKEY on the
// server by its digest, and that key signs the DNSKEY RRset with a signature
// that verifies and is valid now. A matching key tag alone is not enough: the
// tag is a 16 bit checksum and says nothing about the signature.
func anchored(zone string, ds []*dns.DS, keys []*dns.DNSKEY, keyRecords []dns.RR, keySigs []*dns.RRSIG, now time.Time) bool {
	for _, d := range ds {
		for _, key := range keys {
			if key.KeyTag() != d.KeyTag || key.Algorithm != d.Algorithm {
				continue
			}

			digest := key.ToDS(d.DigestType)
			if digest == nil || !strings.EqualFold(digest.Digest, d.Digest) {
				continue
			}

			if signedBy(zone, keyRecords, keySigs, key, now) {
				return true
			}
		}
	}

	return false
}

// signedByAny reports whether one of the keys validly signs the RRset.
func signedByAny(zone string, rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, now time.Time) bool {
	for _, key := range keys {
		if signedBy(zone, rrset, sigs, key, now) {
			return true
		}
	}

	return false
}

// signedBy reports whether one of the signatures is made by the key, verifies
// over the RRset and is valid now.
func signedBy(zone string, rrset []dns.RR, sigs []*dns.RRSIG, key *dns.DNSKEY, now time.Time) bool {
	if len(rrset) == 0 {
		return false
	}

	for _, sig := range sigs {
		if sig.KeyTag != key.KeyTag() || sig.Algorithm != key.Algorithm || !strings.EqualFold(sig.SignerName, zone) {
			continue
		}

		if !sig.ValidityPeriod(now) {
			continue
		}

		if sig.Verify(key, rrset) == nil {
			return true
		}
	}

	return false
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}

	return 0
}
