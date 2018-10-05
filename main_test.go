package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io/ioutil"
	"log"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type opts struct {
	signed  time.Time
	expires time.Time
	privkey crypto.PrivateKey
}

func nullLogger() *log.Logger {
	return log.New(ioutil.Discard, "", log.LstdFlags)
}

func runServer(t *testing.T, opts opts) (string, func()) {

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

	if opts.privkey != nil {
		privkey = opts.privkey
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

		case dns.TypeDNSKEY:

			rrHeader := dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    3600,
			}

			answer := &dns.DNSKEY{
				Hdr:       rrHeader,
				Algorithm: dnskey.Algorithm,
				Flags:     dnskey.Flags,
				Protocol:  dnskey.Protocol,
				PublicKey: dnskey.PublicKey,
			}

			msg.Answer = append(msg.Answer, answer)

		case dns.TypeRRSIG:

			rrHeader := dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    3600,
			}

			answer := &dns.RRSIG{
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

			if err := answer.Sign(privkey.(*ecdsa.PrivateKey), []dns.RR{soa}); err != nil {
				t.Fatalf("couldn't sign SOA record: %v", err)
			}

			msg.Answer = append(msg.Answer, answer)

		case dns.TypeSOA:

			msg.Answer = append(msg.Answer, soa)

		}

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

	return ln.Addr().String(), func() {
		done <- true
	}

}

func TestCollectionOK(t *testing.T) {

	addr, cancel := runServer(t, opts{})
	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, exp := e.collectRecord("example.org", "@", "SOA")

	if !valid {
		t.Fatal("expected record to be valid")
	}

	if exp.Before(time.Now()) {
		t.Fatalf("expected expiration to be in the future, was: %v", exp)
	}

}

func TestCollectionExpired(t *testing.T) {

	addr, cancel := runServer(t, opts{
		signed:  time.Now().Add(14 * 24 * time.Hour),
		expires: time.Now().Add(-time.Hour),
	})

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, exp := e.collectRecord("example.org", "@", "SOA")

	if !valid {
		t.Fatal("expected record to be valid")
	}

	if exp.After(time.Now()) {
		t.Fatalf("expected expiration to be in the past, was: %v", exp)
	}

}

func TestCollectionInvalid(t *testing.T) {

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("couldn't generate fake private key: %v", err)
	}

	addr, cancel := runServer(t, opts{
		privkey: priv,
	})

	defer cancel()

	e := NewDNSSECExporter(time.Second, addr, nullLogger())

	valid, exp := e.collectRecord("example.org", "@", "SOA")

	if valid {
		t.Fatal("expected record to be invalid")
	}

	if exp.Before(time.Now()) {
		t.Fatalf("expected expiration to be in the future, was: %v", exp)
	}

}
