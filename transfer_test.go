package main

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

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
