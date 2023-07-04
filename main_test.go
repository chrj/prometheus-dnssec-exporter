package main

import (
	"crypto/ecdsa"
	"io/ioutil"
	"log"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type opts struct {
	signed          time.Time
	expires         time.Time
	rcode           int
	unauthenticated bool
	noedns0support  bool
	doublesign      bool
	authoritative   bool
}

func nullLogger() *log.Logger {
	return log.New(ioutil.Discard, "", log.LstdFlags)
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

		ns := &dns.NS{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns:      "ns1.example.org.",
		}

		rrHeader := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}

		rrsig_soa := &dns.RRSIG{
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

		// For double signature tests: expires in the past
		rrsig_soa2 := &dns.RRSIG{
			Hdr:         rrHeader,
			TypeCovered: dns.TypeSOA,
			Algorithm:   dnskey.Algorithm,
			Labels:      uint8(dns.CountLabel(q.Name)),
			OrigTtl:     3600,
			Expiration:  uint32(time.Now().Add(-time.Hour).Unix()),
			Inception:   uint32(opts.signed.Unix()),
			KeyTag:      dnskey.KeyTag(),
			SignerName:  q.Name,
		}

		// For AXFR tests: expires before SOA
		rrsig_ns := &dns.RRSIG{
			Hdr:         rrHeader,
			TypeCovered: dns.TypeNS,
			Algorithm:   dnskey.Algorithm,
			Labels:      uint8(dns.CountLabel(q.Name)),
			OrigTtl:     3600,
			Expiration:  uint32(opts.expires.Add(-time.Hour).Unix()),
			Inception:   uint32(opts.signed.Unix()),
			KeyTag:      dnskey.KeyTag(),
			SignerName:  q.Name,
		}

		if err := rrsig_soa.Sign(privkey.(*ecdsa.PrivateKey), []dns.RR{soa}); err != nil {
			t.Fatalf("couldn't sign SOA record: %v", err)
		}

		if err := rrsig_soa2.Sign(privkey.(*ecdsa.PrivateKey), []dns.RR{soa}); err != nil {
			t.Fatalf("couldn't sign SOA record: %v", err)
		}

		if err := rrsig_ns.Sign(privkey.(*ecdsa.PrivateKey), []dns.RR{ns}); err != nil {
			t.Fatalf("couldn't sign NS record: %v", err)
		}

		switch q.Qtype {
		case dns.TypeSOA:
			msg.Answer = append(msg.Answer, soa)
			if ! opts.noedns0support {
				msg.Answer = append(msg.Answer, rrsig_soa)
				if opts.doublesign {
					msg.Answer = append(msg.Answer, rrsig_soa2)
				}
			}
		case dns.TypeNS:
			msg.Answer = append(msg.Answer, ns)
			if ! opts.noedns0support {
				msg.Answer = append(msg.Answer, rrsig_ns)
			}
		case dns.TypeAXFR:
			msg.Answer = append(msg.Answer, soa)
			msg.Answer = append(msg.Answer, rrsig_soa)
			if opts.doublesign {
				msg.Answer = append(msg.Answer, rrsig_soa2)
			}
			msg.Answer = append(msg.Answer, ns)
			msg.Answer = append(msg.Answer, rrsig_ns)
			msg.Answer = append(msg.Answer, soa)
		}

		msg.Authoritative = opts.authoritative || q.Qtype == dns.TypeAXFR
		msg.AuthenticatedData = !opts.unauthenticated && !opts.noedns0support &&
			!opts.authoritative && q.Qtype != dns.TypeAXFR
		msg.Rcode = opts.rcode

		rw.WriteMsg(msg)

	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	server := &dns.Server{
		TsigSecret: map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="},
		Listener: ln,
		Handler:  h,
	}

	go func() {
		server.ActivateAndServe()
	}()

	done := make(chan bool)

	go func() {
		<-done
		server.Shutdown()
		ln.Close()
	}()

	return []string{ln.Addr().String()}, func() {
		done <- true
	}

}

func TestExpirationOK(t *testing.T) {

	addr, cancel := runServer(t, opts{})
	record := Records{"example.org", "@", "SOA"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	_, exp := e.resolve(&record, addr[0])

	if exp.Before(time.Now()) {
		t.Fatalf("expected expiration to be in the future, was: %v", exp)
	}

}

func TestExpired(t *testing.T) {

	addr, cancel := runServer(t, opts{
		signed:  time.Now().Add(14 * 24 * time.Hour),
		expires: time.Now().Add(-time.Hour),
	})
	record := Records{"example.org", "@", "SOA"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	_, exp := e.resolve(&record, addr[0])

	if exp.After(time.Now()) {
		t.Fatalf("expected expiration to be in the past, was: %v", exp)
	}

}

func TestValid(t *testing.T) {

	addr, cancel := runServer(t, opts{
		signed:  time.Now().Add(14 * 24 * time.Hour),
		expires: time.Now().Add(-time.Hour),
	})
	record := Records{"example.org", "@", "SOA"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, _ := e.resolve(&record, addr[0])

	if !valid {
		t.Fatal("expected valid result")
	}

}

func TestInvalidError(t *testing.T) {

	addr, cancel := runServer(t, opts{
		rcode: dns.RcodeServerFailure,
	})
	record := Records{"example.org", "@", "SOA"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, _ := e.resolve(&record, addr[0])

	if valid {
		t.Fatal("expected invalid result")
	}

}

func TestInvalidUnauthenticated(t *testing.T) {

	addr, cancel := runServer(t, opts{
		unauthenticated: true,
	})
	record := Records{"example.org", "@", "SOA"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, _ := e.resolve(&record, addr[0])

	if valid {
		t.Fatal("expected invalid result")
	}

}

func TestNoEDNS0Support(t *testing.T) {

	addr, cancel := runServer(t, opts{
		noedns0support: true,
	})
	record := Records{"example.org", "@", "SOA"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, _ := e.resolve(&record, addr[0])

	if valid {
		t.Fatal("expected invalid result")
	}

}

func TestDoubleSignature(t *testing.T) {

	addr, cancel := runServer(t, opts{
		doublesign: true,
	})
	record := Records{"example.org", "@", "SOA"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	_, exp := e.resolve(&record, addr[0])

	if exp.After(time.Now()) {
		t.Fatalf("expected expiration to be in the past, was: %v", exp)
	}

}

func TestAuthoritativeValid(t *testing.T) {

	addr, cancel := runServer(t, opts{
		authoritative: true,
	})
	record := Records{"example.org", "@", "SOA"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, _ := e.resolve(&record, addr[0])

	if !valid {
		t.Fatal("expected valid result")
	}

}

func TestAxfrValid(t *testing.T) {

	addr, cancel := runServer(t, opts{})
	record := Records{"example.org", "@", "AXFR"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, _ := e.resolve(&record, addr[0])

	if !valid {
		t.Fatal("expected valid result")
	}

}

func TestAxfrExpiresFirst(t *testing.T) {

	addr, cancel := runServer(t, opts{})
	record := Records{"example.org", "@", "AXFR"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	e.resolve(&record, addr[0])

	if record.Type != "NS" {
		t.Fatalf("Expected NS to expire first, got: %v", record.Type)
	}

}

func TestAxfrExpiresFirstDoubleSoa(t *testing.T) {

	addr, cancel := runServer(t, opts{
		doublesign: true,
	})
	record := Records{"example.org", "@", "AXFR"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	e.resolve(&record, addr[0])

	if record.Type != "SOA" {
		t.Fatalf("Expected SOA to expire first, got: %v", record.Type)
	}

}

func TestAxfrRefused(t *testing.T) {

	addr, cancel := runServer(t, opts{
		rcode: dns.RcodeRefused,
	})
	record := Records{"example.org", "@", "AXFR"}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, _ := e.resolve(&record, addr[0])

	if valid {
		t.Fatalf("Expected invalid result")
	}

}

func TestAxfrTSIG(t *testing.T) {

	addr, cancel := runServer(t, opts{})
	record := Records{"example.org", "@", "AXFR"}
	key := Keys{"hmac-sha256.", "axfr.", "so6ZGir4GPAqINNh9U5c3A=="}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	e.dnsClient.TsigSecret = map[string]string{key.Name: key.Secret}
	e.TsigInfo = map[Records]*Keys{record: &key}

	valid, _ := e.resolve(&record, addr[0])

	if !valid {
		t.Fatal("expected valid result")
	}

}

func TestAxfrTSIGWrong(t *testing.T) {

	addr, cancel := runServer(t, opts{})
	record := Records{"example.org", "@", "AXFR"}
	key := Keys{"hmac-sha256.", "axfr.", "YmFkYmFkYmFkYmFkCg=="}

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	e.dnsClient.TsigSecret = map[string]string{key.Name: key.Secret}
	e.TsigInfo = map[Records]*Keys{record: &key}

	valid, _ := e.resolve(&record, addr[0])

	if valid {
		t.Fatal("expected invalid result")
	}

}
