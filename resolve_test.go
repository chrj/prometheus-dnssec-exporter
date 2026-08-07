package main

import (
	"context"
	"crypto/ecdsa"
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
