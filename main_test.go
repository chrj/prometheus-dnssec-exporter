package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type opts struct {
	signed          time.Time
	expires         time.Time
	rcode           int
	unauthenticated bool
	noedns0support  bool
}

func nullLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func soaRecord() Record {
	return Record{Zone: "example.org", Record: "@", Type: "SOA"}
}

func runServer(t *testing.T, opts opts) ([]string, func()) {

	if opts.signed.IsZero() {
		opts.signed = time.Now().Add(-time.Hour)
	}

	if opts.expires.IsZero() {
		opts.expires = time.Now().Add(14 * 24 * time.Hour)
	}

	dnskey := &dns.DNSKEY{
		Algorithm: dns.ECDSAP256SHA256,
		Flags:     dns.ZONE,
		Protocol:  3,
	}

	privkey, err := dnskey.Generate(256)
	if err != nil {
		t.Fatalf("couldn't generate private key: %v", err)
	}

	h := dns.NewServeMux()
	h.HandleFunc("example.org.", func(rw dns.ResponseWriter, msg *dns.Msg) {

		q := msg.Question[0]

		soa := &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns:      "ns1.example.org.",
			Mbox:    "test.example.org.",
			Serial:  1,
			Refresh: 14400,
			Retry:   3600,
			Expire:  7200,
			Minttl:  60,
		}

		switch q.Qtype {

		case dns.TypeSOA:

			rrHeader := dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    3600,
			}
			msg.Answer = append(msg.Answer, soa)

			if opts.noedns0support {
				break
			}

			rrsig := &dns.RRSIG{
				Hdr:         rrHeader,
				TypeCovered: dns.TypeSOA,
				Algorithm:   dnskey.Algorithm,
				Labels:      uint8(dns.CountLabel(q.Name)),
				OrigTtl:     3600,
				Expiration:  uint32(opts.expires.Unix()),
				Inception:   uint32(opts.signed.Unix()),
				KeyTag:      dnskey.KeyTag(),
				SignerName:  q.Name,
			}

			if err := rrsig.Sign(privkey.(*ecdsa.PrivateKey), []dns.RR{soa}); err != nil {
				t.Errorf("couldn't sign SOA record: %v", err)
				return
			}

			msg.Answer = append(msg.Answer, rrsig)

		}

		msg.AuthenticatedData = !opts.unauthenticated && !opts.noedns0support
		msg.Rcode = opts.rcode

		if err := rw.WriteMsg(msg); err != nil {
			t.Errorf("couldn't write message: %v", err)
		}

	})

	var lc net.ListenConfig

	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	server := &dns.Server{
		Listener: ln,
		Handler:  h,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	done := make(chan bool)

	go func() {
		<-done
		_ = server.Shutdown()
		_ = ln.Close()
	}()

	return []string{ln.Addr().String()}, func() {
		done <- true
	}

}

func TestExpirationOK(t *testing.T) {

	addr, cancel := runServer(t, opts{})
	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	_, exp := e.resolve(context.Background(), soaRecord(), addr[0])

	if exp.Before(time.Now()) {
		t.Fatalf("expected expiration to be in the future, was: %v", exp)
	}

}

func TestExpired(t *testing.T) {

	addr, cancel := runServer(t, opts{
		signed:  time.Now().Add(14 * 24 * time.Hour),
		expires: time.Now().Add(-time.Hour),
	})

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	_, exp := e.resolve(context.Background(), soaRecord(), addr[0])

	if exp.After(time.Now()) {
		t.Fatalf("expected expiration to be in the past, was: %v", exp)
	}

}

func TestValid(t *testing.T) {

	addr, cancel := runServer(t, opts{
		signed:  time.Now().Add(14 * 24 * time.Hour),
		expires: time.Now().Add(-time.Hour),
	})

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, _ := e.resolve(context.Background(), soaRecord(), addr[0])

	if !valid {
		t.Fatal("expected valid result")
	}

}

func TestInvalidError(t *testing.T) {

	addr, cancel := runServer(t, opts{
		rcode: dns.RcodeServerFailure,
	})

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, _ := e.resolve(context.Background(), soaRecord(), addr[0])

	if valid {
		t.Fatal("expected invalid result")
	}

}

func TestInvalidUnauthenticated(t *testing.T) {

	addr, cancel := runServer(t, opts{
		unauthenticated: true,
	})

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, _ := e.resolve(context.Background(), soaRecord(), addr[0])

	if valid {
		t.Fatal("expected invalid result")
	}

}

func TestNoEDNS0Support(t *testing.T) {

	addr, cancel := runServer(t, opts{
		noedns0support: true,
	})

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, _ := e.resolve(context.Background(), soaRecord(), addr[0])

	if valid {
		t.Fatal("expected invalid result")
	}

}

// Authoritative servers serve RRSIGs but never set the AD bit. The expiry
// metric must still be reported so those servers can be monitored.
func TestExpiryReportedWithoutAuthenticatedData(t *testing.T) {

	addr, cancel := runServer(t, opts{
		unauthenticated: true,
		expires:         time.Unix(2000000000, 0),
	})

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())
	e.Records = []Record{soaRecord()}

	expected := `
# HELP dnssec_zone_record_earliest_rrsig_expiry Earliest expiring RRSIG covering the record on resolver in unixtime
# TYPE dnssec_zone_record_earliest_rrsig_expiry gauge
dnssec_zone_record_earliest_rrsig_expiry{record="@",resolver="` + addr[0] + `",type="SOA",zone="example.org"} 2e+09
# HELP dnssec_zone_record_resolves Does the record resolve using the specified DNSSEC enabled resolvers
# TYPE dnssec_zone_record_resolves gauge
dnssec_zone_record_resolves{record="@",resolver="` + addr[0] + `",type="SOA",zone="example.org"} 0
`

	if err := testutil.CollectAndCompare(e, strings.NewReader(expected),
		"dnssec_zone_record_earliest_rrsig_expiry", "dnssec_zone_record_resolves"); err != nil {
		t.Fatalf("unexpected metrics: %v", err)
	}

}

// A record without an RRSIG must not report a days_left value at all. Reporting
// a bogus one made transient failures page immediately.
func TestNoDaysLeftWithoutSignature(t *testing.T) {

	addr, cancel := runServer(t, opts{
		noedns0support: true,
	})

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())
	e.Records = []Record{soaRecord()}

	count := testutil.CollectAndCount(e, "dnssec_zone_record_days_left")
	if count != 0 {
		t.Fatalf("expected no days_left series, got %d", count)
	}

}

// An unreachable resolver must leave every signature metric absent rather than
// emitting a stale or bogus value.
func TestUnreachableResolverReportsOnlyResolves(t *testing.T) {

	// Port 1 on the loopback address refuses connections immediately.
	e := NewDNSSECExporter(time.Second, []string{"127.0.0.1:1"}, nullLogger())
	e.Records = []Record{soaRecord()}

	expected := `
# HELP dnssec_zone_record_resolves Does the record resolve using the specified DNSSEC enabled resolvers
# TYPE dnssec_zone_record_resolves gauge
dnssec_zone_record_resolves{record="@",resolver="127.0.0.1:1",type="SOA",zone="example.org"} 0
`

	if err := testutil.CollectAndCompare(e, strings.NewReader(expected)); err != nil {
		t.Fatalf("unexpected metrics: %v", err)
	}

}

func TestCollectUsesFirstResolverForDaysLeft(t *testing.T) {

	addr, cancel := runServer(t, opts{})
	defer cancel()

	// The second resolver refuses connections, so only the first can contribute.
	e := NewDNSSECExporter(time.Second, []string{addr[0], "127.0.0.1:1"}, nullLogger())
	e.Records = []Record{soaRecord()}

	if count := testutil.CollectAndCount(e, "dnssec_zone_record_days_left"); count != 1 {
		t.Fatalf("expected exactly one days_left series, got %d", count)
	}

	if count := testutil.CollectAndCount(e, "dnssec_zone_record_resolves"); count != 2 {
		t.Fatalf("expected a resolves series per resolver, got %d", count)
	}

}

// zoneOpts configures the AXFR test server.
type zoneOpts struct {
	// expirations are the RRSIG expiration times to serve, one signed A record
	// each, named a0, a1 and so on.
	expirations []time.Time

	// tsigSecret, when set, makes the server require and check a TSIG.
	tsigSecret map[string]string

	// refuse makes the server answer AXFR with REFUSED.
	refuse bool

	// unsigned serves the zone without any RRSIG.
	unsigned bool
}

// runZoneServer serves example.com over AXFR. It returns the server address and
// a function that stops it.
func runZoneServer(t *testing.T, opts zoneOpts) (string, func()) {

	const zone = "example.com."

	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Algorithm: dns.ECDSAP256SHA256,
		Flags:     dns.ZONE,
		Protocol:  3,
	}

	privkey, err := dnskey.Generate(256)
	if err != nil {
		t.Fatalf("couldn't generate private key: %v", err)
	}

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1." + zone,
		Mbox:    "test." + zone,
		Serial:  1,
		Refresh: 14400,
		Retry:   3600,
		Expire:  7200,
		Minttl:  60,
	}

	records := []dns.RR{soa}

	for i, expires := range opts.expirations {
		name := fmt.Sprintf("a%d.%s", i, zone)

		a := &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   net.IPv4(127, 0, 0, byte(i+1)),
		}

		records = append(records, a)

		if opts.unsigned {
			continue
		}

		rrsig := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeA,
			Algorithm:   dnskey.Algorithm,
			Labels:      uint8(dns.CountLabel(name)),
			OrigTtl:     3600,
			Expiration:  uint32(expires.Unix()),
			Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
			KeyTag:      dnskey.KeyTag(),
			SignerName:  zone,
		}

		if err := rrsig.Sign(privkey.(*ecdsa.PrivateKey), []dns.RR{a}); err != nil {
			t.Fatalf("couldn't sign %s: %v", name, err)
		}

		records = append(records, rrsig)
	}

	// A zone transfer ends with the SOA repeated.
	records = append(records, soa)

	h := dns.NewServeMux()
	h.HandleFunc(zone, func(rw dns.ResponseWriter, msg *dns.Msg) {

		if opts.refuse {
			reply := &dns.Msg{}
			reply.SetRcode(msg, dns.RcodeRefused)

			if err := rw.WriteMsg(reply); err != nil {
				t.Errorf("couldn't write refusal: %v", err)
			}

			return
		}

		tr := &dns.Transfer{}
		envelopes := make(chan *dns.Envelope)

		go func() {
			envelopes <- &dns.Envelope{RR: records}
			close(envelopes)
		}()

		if err := tr.Out(rw, msg, envelopes); err != nil {
			t.Errorf("couldn't write zone: %v", err)
		}

	})

	var lc net.ListenConfig

	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	server := &dns.Server{
		Listener:   ln,
		Handler:    h,
		TsigSecret: opts.tsigSecret,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	done := make(chan bool)

	go func() {
		<-done
		_ = server.Shutdown()
		_ = ln.Close()
	}()

	return ln.Addr().String(), func() { done <- true }

}

// zoneExporter builds an exporter for a single zone and runs Validate, so the
// key index is built the same way it is at start.
func zoneExporter(t *testing.T, zone Zone, keys []Key) *Exporter {

	e := NewDNSSECExporter(2*time.Second, []string{"127.0.0.1:53"}, nullLogger())
	e.Zones = []Zone{zone}
	e.Keys = keys

	if err := e.Validate(); err != nil {
		t.Fatalf("expected a valid configuration, got: %v", err)
	}

	return e
}

// The exporter must report the record in the zone that expires first, not the
// first record it happens to read.
func TestZoneTransferReportsEarliestSignature(t *testing.T) {

	addr, cancel := runZoneServer(t, zoneOpts{
		expirations: []time.Time{
			time.Unix(2100000000, 0),
			time.Unix(2000000000, 0), // the earliest
			time.Unix(2200000000, 0),
		},
	})

	defer cancel()

	e := zoneExporter(t, Zone{Zone: "example.com", Server: addr}, nil)

	expected := `
# HELP dnssec_zone_record_earliest_rrsig_expiry Earliest expiring RRSIG covering the record on resolver in unixtime
# TYPE dnssec_zone_record_earliest_rrsig_expiry gauge
dnssec_zone_record_earliest_rrsig_expiry{record="a1.example.com.",resolver="` + addr + `",type="A",zone="example.com"} 2e+09
# HELP dnssec_zone_transfer_success Did the zone transfer from the configured server succeed
# TYPE dnssec_zone_transfer_success gauge
dnssec_zone_transfer_success{server="` + addr + `",zone="example.com"} 1
`

	if err := testutil.CollectAndCompare(e, strings.NewReader(expected),
		"dnssec_zone_record_earliest_rrsig_expiry", "dnssec_zone_transfer_success"); err != nil {
		t.Fatalf("unexpected metrics: %v", err)
	}

}

func TestZoneTransferWithTSIG(t *testing.T) {

	const (
		keyName   = "testkey."
		keySecret = "mvgDxfYTSe8L+pp7h4r+PIeTc67YTPhGWZrhmIi2Rpo="
	)

	addr, cancel := runZoneServer(t, zoneOpts{
		expirations: []time.Time{time.Unix(2000000000, 0)},
		tsigSecret:  map[string]string{keyName: keySecret},
	})

	defer cancel()

	e := zoneExporter(t,
		Zone{Zone: "example.com", Server: addr, Key: keyName},
		[]Key{{Name: keyName, Algorithm: "hmac-sha256", Secret: keySecret}},
	)

	if got := testutil.ToFloat64(collectOne(t, e, "dnssec_zone_transfer_success")); got != 1 {
		t.Fatalf("transfer_success = %v, want 1", got)
	}

}

// A transfer signed with the wrong secret must fail, and must not report a
// signature that the exporter never authenticated.
func TestZoneTransferWrongTSIGSecret(t *testing.T) {

	const keyName = "testkey."

	addr, cancel := runZoneServer(t, zoneOpts{
		expirations: []time.Time{time.Unix(2000000000, 0)},
		tsigSecret:  map[string]string{keyName: "mvgDxfYTSe8L+pp7h4r+PIeTc67YTPhGWZrhmIi2Rpo="},
	})

	defer cancel()

	e := zoneExporter(t,
		Zone{Zone: "example.com", Server: addr, Key: keyName},
		[]Key{{Name: keyName, Algorithm: "hmac-sha256", Secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
	)

	expected := `
# HELP dnssec_zone_transfer_success Did the zone transfer from the configured server succeed
# TYPE dnssec_zone_transfer_success gauge
dnssec_zone_transfer_success{server="` + addr + `",zone="example.com"} 0
`

	if err := testutil.CollectAndCompare(e, strings.NewReader(expected)); err != nil {
		t.Fatalf("unexpected metrics: %v", err)
	}

}

// A refused transfer must report the failure and leave the signature metrics
// absent, so an alert cannot read a value that was never measured.
func TestZoneTransferRefused(t *testing.T) {

	addr, cancel := runZoneServer(t, zoneOpts{refuse: true})
	defer cancel()

	e := zoneExporter(t, Zone{Zone: "example.com", Server: addr}, nil)

	expected := `
# HELP dnssec_zone_transfer_success Did the zone transfer from the configured server succeed
# TYPE dnssec_zone_transfer_success gauge
dnssec_zone_transfer_success{server="` + addr + `",zone="example.com"} 0
`

	if err := testutil.CollectAndCompare(e, strings.NewReader(expected)); err != nil {
		t.Fatalf("unexpected metrics: %v", err)
	}

}

// An unsigned zone transfers correctly but has nothing to report.
func TestZoneTransferUnsignedZone(t *testing.T) {

	addr, cancel := runZoneServer(t, zoneOpts{
		expirations: []time.Time{time.Unix(2000000000, 0)},
		unsigned:    true,
	})

	defer cancel()

	e := zoneExporter(t, Zone{Zone: "example.com", Server: addr}, nil)

	if got := testutil.ToFloat64(collectOne(t, e, "dnssec_zone_transfer_success")); got != 1 {
		t.Fatalf("transfer_success = %v, want 1", got)
	}

	if count := testutil.CollectAndCount(e, "dnssec_zone_record_earliest_rrsig_expiry"); count != 0 {
		t.Fatalf("expected no expiry series for an unsigned zone, got %d", count)
	}

}

// Records and zones must be collectable by the same process. This was the
// limitation that kept the original change from landing.
func TestRecordsAndZonesTogether(t *testing.T) {

	recordAddr, cancelRecord := runServer(t, opts{})
	defer cancelRecord()

	zoneAddr, cancelZone := runZoneServer(t, zoneOpts{
		expirations: []time.Time{time.Unix(2000000000, 0)},
	})

	defer cancelZone()

	e := NewDNSSECExporter(2*time.Second, recordAddr, nullLogger())
	e.Records = []Record{soaRecord()}
	e.Zones = []Zone{{Zone: "example.com", Server: zoneAddr}}

	if err := e.Validate(); err != nil {
		t.Fatalf("expected a valid configuration, got: %v", err)
	}

	// One from the record on its resolver, one from the zone on its own server.
	if count := testutil.CollectAndCount(e, "dnssec_zone_record_days_left"); count != 2 {
		t.Fatalf("expected a days_left series for the record and the zone, got %d", count)
	}

	if count := testutil.CollectAndCount(e, "dnssec_zone_record_resolves"); count != 1 {
		t.Fatalf("expected one resolves series, got %d", count)
	}

	if count := testutil.CollectAndCount(e, "dnssec_zone_transfer_success"); count != 1 {
		t.Fatalf("expected one transfer_success series, got %d", count)
	}

}

// collectOne gathers the exporter and returns the single metric with the given
// name, so a test can read its value.
func collectOne(t *testing.T, e *Exporter, name string) prometheus.Gauge {

	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(e); err != nil {
		t.Fatalf("couldn't register exporter: %v", err)
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("couldn't gather metrics: %v", err)
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}

		if len(family.GetMetric()) != 1 {
			t.Fatalf("expected one %s series, got %d", name, len(family.GetMetric()))
		}

		g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "proxy"})
		g.Set(family.GetMetric()[0].GetGauge().GetValue())

		return g
	}

	t.Fatalf("metric %s was not reported", name)

	return nil

}

func TestValidateKeysAndZones(t *testing.T) {

	tests := []struct {
		name    string
		zones   []Zone
		keys    []Key
		wantErr string
	}{
		{
			name:  "zone without a key",
			zones: []Zone{{Zone: "example.com", Server: "127.0.0.1:53"}},
		},
		{
			name:  "zone with a key",
			zones: []Zone{{Zone: "example.com", Key: "k."}},
			keys:  []Key{{Name: "k.", Algorithm: "hmac-sha256", Secret: "c2VjcmV0"}},
		},
		{
			name:  "key name without a trailing dot still matches",
			zones: []Zone{{Zone: "example.com", Key: "k"}},
			keys:  []Key{{Name: "k", Algorithm: "hmac-sha256", Secret: "c2VjcmV0"}},
		},
		{
			name:    "zone names a key that does not exist",
			zones:   []Zone{{Zone: "example.com", Key: "missing."}},
			wantErr: "which no [[keys]] section defines",
		},
		{
			name:    "zone without a name",
			zones:   []Zone{{Server: "127.0.0.1:53"}},
			wantErr: "a zone has no name",
		},
		{
			name:    "duplicate zone",
			zones:   []Zone{{Zone: "example.com"}, {Zone: "example.com."}},
			wantErr: "configured more than once",
		},
		{
			name:    "server without a port",
			zones:   []Zone{{Zone: "example.com", Server: "127.0.0.1"}},
			wantErr: "needs a port",
		},
		{
			name:    "key without a secret",
			zones:   []Zone{{Zone: "example.com"}},
			keys:    []Key{{Name: "k.", Algorithm: "hmac-sha256"}},
			wantErr: "has no secret",
		},
		{
			name:    "key with an unknown algorithm",
			zones:   []Zone{{Zone: "example.com"}},
			keys:    []Key{{Name: "k.", Algorithm: "hmac-nope", Secret: "c2VjcmV0"}},
			wantErr: "unknown algorithm",
		},
		{
			name:    "duplicate key",
			zones:   []Zone{{Zone: "example.com"}},
			keys:    []Key{{Name: "k.", Algorithm: "hmac-sha256", Secret: "c2VjcmV0"}, {Name: "k", Algorithm: "hmac-sha256", Secret: "c2VjcmV0"}},
			wantErr: "configured more than once",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewDNSSECExporter(time.Second, []string{"127.0.0.1:53"}, nullLogger())
			e.Zones = tt.zones
			e.Keys = tt.keys

			err := e.Validate()

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error that contains %q, got nil", tt.wantErr)
				}

				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected an error that contains %q, got: %v", tt.wantErr, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}

}

// A TSIG secret must never reach a log line or an error message.
func TestKeyDoesNotLeakSecret(t *testing.T) {

	const secret = "mvgDxfYTSe8L+pp7h4r+PIeTc67YTPhGWZrhmIi2Rpo="

	key := Key{Name: "k.", Algorithm: "hmac-sha256.", Secret: secret}

	var buf strings.Builder

	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("using key", "key", key)

	if strings.Contains(buf.String(), secret) {
		t.Fatalf("the log line contains the secret: %s", buf.String())
	}

	if strings.Contains(key.String(), secret) {
		t.Fatalf("String() contains the secret: %s", key.String())
	}

	if strings.Contains(fmt.Sprintf("%v", key), secret) {
		t.Fatalf("the formatted value contains the secret: %v", key)
	}

}

func TestHostname(t *testing.T) {

	tests := []struct {
		name   string
		zone   string
		record string
		want   string
	}{
		{"apex", "example.org", "@", "example.org."},
		{"subdomain", "example.org", "www", "www.example.org."},
		{"absolute zone", "example.org.", "@", "example.org."},
		{"absolute subdomain", "example.org.", "www", "www.example.org."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostname(tt.zone, tt.record); got != tt.want {
				t.Fatalf("hostname(%q, %q) = %q, want %q", tt.zone, tt.record, got, tt.want)
			}
		})
	}

}

func TestParseResolvers(t *testing.T) {

	tests := []struct {
		name    string
		list    string
		want    []string
		wantErr bool
	}{
		{"with ports", "8.8.8.8:53,1.1.1.1:53", []string{"8.8.8.8:53", "1.1.1.1:53"}, false},
		{"default port", "8.8.8.8,1.1.1.1", []string{"8.8.8.8:53", "1.1.1.1:53"}, false},
		{"ipv6 default port", "2001:4860:4860::8888", []string{"[2001:4860:4860::8888]:53"}, false},
		{"ipv6 with port", "[2001:4860:4860::8888]:53", []string{"[2001:4860:4860::8888]:53"}, false},
		{"hostname", "dns.example.org", []string{"dns.example.org:53"}, false},
		{"whitespace and blanks", " 8.8.8.8 , ,1.1.1.1:5353", []string{"8.8.8.8:53", "1.1.1.1:5353"}, false},
		{"empty", "", nil, true},
		{"only separators", ",,", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseResolvers(tt.list)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseResolvers(%q) = %v, want error", tt.list, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseResolvers(%q) returned error: %v", tt.list, err)
			}

			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("parseResolvers(%q) = %v, want %v", tt.list, got, tt.want)
			}
		})
	}

}

func TestLoadExporter(t *testing.T) {

	tests := []struct {
		name        string
		data        string
		wantRecords []Record
		wantErr     string
	}{
		{
			name: "sample configuration",
			data: `
[[records]]
  zone = "ietf.org"
  record = "@"
  type = "SOA"

[[records]]
  zone = "verisigninc.com"
  record = "@"
  type = "SOA"
`,
			wantRecords: []Record{
				{Zone: "ietf.org", Record: "@", Type: "SOA"},
				{Zone: "verisigninc.com", Record: "@", Type: "SOA"},
			},
		},
		{
			name: "comments and mixed quoting",
			data: `
# check the apex
[[records]]
  zone = 'example.org'
  record = "@"
  type = "SOA"
`,
			wantRecords: []Record{{Zone: "example.org", Record: "@", Type: "SOA"}},
		},
		{
			name: "misspelled key",
			data: `
[[records]]
  zne = "example.org"
  record = "@"
  type = "SOA"
`,
			wantErr: "unknown keys",
		},
		{
			name:    "syntax error",
			data:    "[[records]\n",
			wantErr: "parse configuration file",
		},
		{
			name:    "nothing configured",
			data:    "\n",
			wantErr: "nothing configured to check",
		},
		{
			name: "unknown record type",
			data: `
[[records]]
  zone = "example.org"
  record = "@"
  type = "NOPE"
`,
			wantErr: "unknown type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dnssec-checks")

			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatalf("couldn't write configuration file: %v", err)
			}

			e, err := loadExporter(path, time.Second, []string{"127.0.0.1:53"}, nullLogger())

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error that contains %q, got nil", tt.wantErr)
				}

				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected an error that contains %q, got: %v", tt.wantErr, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if !slices.Equal(e.Records, tt.wantRecords) {
				t.Fatalf("records = %v, want %v", e.Records, tt.wantRecords)
			}
		})
	}

}

// The configuration file must carry zones and keys through to the exporter. The
// strict check on unknown settings rejects a table that the schema forgets, so
// leaving one out turns a working file into a start-up error.
func TestLoadExporterReadsZonesAndKeys(t *testing.T) {

	data := `
[[records]]
  zone = "example.org"
  record = "@"
  type = "SOA"

[[zones]]
  zone = "example.com"
  server = "127.0.0.1:5353"
  key = "mysecretkey."

[[keys]]
  name = "mysecretkey."
  algorithm = "hmac-sha256."
  secret = "mvgDxfYTSe8L+pp7h4r+PIeTc67YTPhGWZrhmIi2Rpo="
`

	path := filepath.Join(t.TempDir(), "dnssec-checks")

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("couldn't write configuration file: %v", err)
	}

	e, err := loadExporter(path, time.Second, []string{"127.0.0.1:53"}, nullLogger())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	wantZones := []Zone{{Zone: "example.com", Server: "127.0.0.1:5353", Key: "mysecretkey."}}
	if !slices.Equal(e.Zones, wantZones) {
		t.Fatalf("zones = %v, want %v", e.Zones, wantZones)
	}

	if len(e.Keys) != 1 || e.Keys[0].Name != "mysecretkey." {
		t.Fatalf("keys = %v, want one key named mysecretkey.", e.Keys)
	}

	// Validate indexes the keys, so the zone must find the one it names.
	if _, ok := e.keys["mysecretkey."]; !ok {
		t.Fatalf("the key index does not hold mysecretkey.: %v", e.keys)
	}

}

func TestLoadExporterMissingFile(t *testing.T) {

	path := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := loadExporter(path, time.Second, []string{"127.0.0.1:53"}, nullLogger())
	if err == nil {
		t.Fatal("expected an error for a missing configuration file")
	}

	if !strings.Contains(err.Error(), "open configuration file") {
		t.Fatalf("expected an error about opening the file, got: %v", err)
	}

}

func TestValidate(t *testing.T) {

	tests := []struct {
		name    string
		records []Record
		wantErr bool
	}{
		{"valid", []Record{{Zone: "example.org", Record: "@", Type: "SOA"}}, false},
		{"valid subdomain", []Record{{Zone: "example.org", Record: "www", Type: "A"}}, false},
		{"no records", nil, true},
		{"missing zone", []Record{{Record: "@", Type: "SOA"}}, true},
		{"missing record", []Record{{Zone: "example.org", Type: "SOA"}}, true},
		{"unknown type", []Record{{Zone: "example.org", Record: "@", Type: "NOPE"}}, true},
		{"duplicate", []Record{
			{Zone: "example.org", Record: "@", Type: "SOA"},
			{Zone: "example.org", Record: "@", Type: "SOA"},
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewDNSSECExporter(time.Second, []string{"127.0.0.1:53"}, nullLogger())
			e.Records = tt.records

			err := e.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}

}
