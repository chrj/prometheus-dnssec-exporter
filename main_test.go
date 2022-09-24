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
				t.Fatalf("couldn't sign SOA record: %v", err)
			}

			msg.Answer = append(msg.Answer, rrsig)

		}

		msg.AuthenticatedData = !opts.unauthenticated && !opts.noedns0support
		msg.Rcode = opts.rcode

		rw.WriteMsg(msg)

	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	server := &dns.Server{
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
	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	_, exp := e.resolve("example.org", "@", "SOA", addr[0])

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

	_, exp := e.resolve("example.org", "@", "SOA", addr[0])

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

	valid, _ := e.resolve("example.org", "@", "SOA", addr[0])

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

	valid, _ := e.resolve("example.org", "@", "SOA", addr[0])

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

	valid, _ := e.resolve("example.org", "@", "SOA", addr[0])

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

	valid, _ := e.resolve("example.org", "@", "SOA", addr[0])

	if valid {
		t.Fatal("expected invalid result")
	}

}
