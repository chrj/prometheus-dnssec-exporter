package main

import (
	"crypto"
	"crypto/ecdsa"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const chainZone = "example.com."

// chainKey is a DNSKEY with its private key, so a test can sign with it.
type chainKey struct {
	key  *dns.DNSKEY
	priv crypto.Signer
}

func newChainKey(t *testing.T, flags uint16) chainKey {

	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: chainZone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Algorithm: dns.ECDSAP256SHA256,
		Flags:     flags,
		Protocol:  3,
	}

	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("couldn't generate key: %v", err)
	}

	return chainKey{key: key, priv: priv.(*ecdsa.PrivateKey)}
}

func (k chainKey) sign(t *testing.T, rrset []dns.RR, expires time.Time) *dns.RRSIG {

	hdr := rrset[0].Header()

	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: hdr.Ttl},
		TypeCovered: hdr.Rrtype,
		Algorithm:   k.key.Algorithm,
		Labels:      uint8(dns.CountLabel(hdr.Name)),
		OrigTtl:     hdr.Ttl,
		Expiration:  uint32(expires.Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      k.key.KeyTag(),
		SignerName:  chainZone,
	}

	if err := sig.Sign(k.priv, rrset); err != nil {
		t.Fatalf("couldn't sign %s: %v", dns.TypeToString[hdr.Rrtype], err)
	}

	return sig
}

// chainZoneData is what the test servers answer. The parent server answers DS,
// the zone server answers DNSKEY and SOA.
type chainZoneData struct {
	ds         []dns.RR
	dnskey     []dns.RR
	dnskeySigs []dns.RR
	soa        []dns.RR
	soaSigs    []dns.RR
}

// signedZone builds a zone the usual way: the KSK signs the DNSKEY RRset, the
// ZSK signs the SOA, and the parent holds a DS for the KSK.
func signedZone(t *testing.T) (chainZoneData, chainKey, chainKey) {

	ksk := newChainKey(t, dns.ZONE|dns.SEP)
	zsk := newChainKey(t, dns.ZONE)

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: chainZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1." + chainZone,
		Mbox:    "hostmaster." + chainZone,
		Serial:  1,
		Refresh: 14400,
		Retry:   3600,
		Expire:  604800,
		Minttl:  300,
	}

	expires := time.Unix(2100000000, 0)
	dnskey := []dns.RR{ksk.key, zsk.key}

	return chainZoneData{
		ds:         []dns.RR{ksk.key.ToDS(dns.SHA256)},
		dnskey:     dnskey,
		dnskeySigs: []dns.RR{ksk.sign(t, dnskey, expires)},
		soa:        []dns.RR{soa},
		soaSigs:    []dns.RR{zsk.sign(t, []dns.RR{soa}, expires)},
	}, ksk, zsk
}

// runChainServer answers queries for example.com from data. With refuse set it
// answers everything with REFUSED.
func runChainServer(t *testing.T, data chainZoneData, refuse bool) (string, func()) {

	h := dns.NewServeMux()
	h.HandleFunc(chainZone, func(rw dns.ResponseWriter, msg *dns.Msg) {

		reply := &dns.Msg{}
		reply.SetReply(msg)
		reply.Authoritative = true

		if refuse {
			reply.SetRcode(msg, dns.RcodeRefused)
		} else {
			switch msg.Question[0].Qtype {
			case dns.TypeDS:
				reply.Answer = append(reply.Answer, data.ds...)
			case dns.TypeDNSKEY:
				reply.Answer = append(append(reply.Answer, data.dnskey...), data.dnskeySigs...)
			case dns.TypeSOA:
				reply.Answer = append(append(reply.Answer, data.soa...), data.soaSigs...)
			}
		}

		if err := rw.WriteMsg(reply); err != nil {
			t.Errorf("couldn't write reply: %v", err)
		}

	})

	var lc net.ListenConfig

	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	server := &dns.Server{Listener: ln, Handler: h}

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

// chainExporter serves data from a parent and a zone server and returns an
// exporter for the chain, plus the two server addresses.
func chainExporter(t *testing.T, data chainZoneData) (*Exporter, string, string) {

	parent, stopParent := runChainServer(t, data, false)
	t.Cleanup(stopParent)

	server, stopServer := runChainServer(t, data, false)
	t.Cleanup(stopServer)

	e := NewDNSSECExporter(2*time.Second, []string{"127.0.0.1:53"}, nullLogger())
	e.Chains = []Chain{{Zone: "example.com", ParentServers: []string{parent}, Servers: []string{server}}}

	if err := e.Validate(); err != nil {
		t.Fatalf("expected a valid configuration, got: %v", err)
	}

	return e, parent, server
}

func chainValue(t *testing.T, e *Exporter, name string) float64 {
	return testutil.ToFloat64(collectOne(t, e, name))
}

func TestChainValid(t *testing.T) {

	data, _, _ := signedZone(t)
	e, parent, server := chainExporter(t, data)

	expected := `
# HELP dnssec_chain_dnskey_records Number of DNSKEY records the server publishes for the zone
# TYPE dnssec_chain_dnskey_records gauge
dnssec_chain_dnskey_records{server="` + server + `",zone="example.com"} 2
# HELP dnssec_chain_ds_match Does a DS record at the parent match a DNSKEY on the server that validly signs the DNSKEY RRset
# TYPE dnssec_chain_ds_match gauge
dnssec_chain_ds_match{server="` + server + `",zone="example.com"} 1
# HELP dnssec_chain_ds_records Number of DS records for the zone at the parent
# TYPE dnssec_chain_ds_records gauge
dnssec_chain_ds_records{zone="example.com"} 1
# HELP dnssec_chain_earliest_rrsig_expiry Earliest expiring RRSIG over the DNSKEY and SOA RRsets on the server in unixtime
# TYPE dnssec_chain_earliest_rrsig_expiry gauge
dnssec_chain_earliest_rrsig_expiry{server="` + server + `",zone="example.com"} 2.1e+09
# HELP dnssec_chain_query_success Did the server answer the queries for the chain check
# TYPE dnssec_chain_query_success gauge
dnssec_chain_query_success{server="` + parent + `",zone="example.com"} 1
dnssec_chain_query_success{server="` + server + `",zone="example.com"} 1
# HELP dnssec_chain_soa_signature_valid Does the SOA on the server carry a valid RRSIG from one of the server's DNSKEYs
# TYPE dnssec_chain_soa_signature_valid gauge
dnssec_chain_soa_signature_valid{server="` + server + `",zone="example.com"} 1
`

	if err := testutil.CollectAndCompare(e, strings.NewReader(expected)); err != nil {
		t.Fatalf("unexpected metrics: %v", err)
	}

}

// The case this check exists for: the parent still publishes a DS for a key the
// zone no longer serves. Every signature in the zone is valid, and a resolver
// with the old key in its cache keeps validating, but the chain is broken.
func TestChainDSForRetiredKey(t *testing.T) {

	data, _, _ := signedZone(t)
	retired := newChainKey(t, dns.ZONE|dns.SEP)
	data.ds = []dns.RR{retired.key.ToDS(dns.SHA256)}

	e, _, _ := chainExporter(t, data)

	if got := chainValue(t, e, "dnssec_chain_ds_match"); got != 0 {
		t.Fatalf("ds_match = %v, want 0", got)
	}

	if got := chainValue(t, e, "dnssec_chain_soa_signature_valid"); got != 1 {
		t.Fatalf("soa_signature_valid = %v, want 1", got)
	}

}

// A DS with the right key tag and algorithm but a different digest must not
// count as a match. The key tag is a 16 bit checksum, not an identity.
func TestChainDSDigestMismatch(t *testing.T) {

	data, _, _ := signedZone(t)
	ds := data.ds[0].(*dns.DS)
	ds.Digest = strings.Repeat("0", len(ds.Digest))

	e, _, _ := chainExporter(t, data)

	if got := chainValue(t, e, "dnssec_chain_ds_match"); got != 0 {
		t.Fatalf("ds_match = %v, want 0", got)
	}

}

// The key the DS points to must itself sign the DNSKEY RRset. A KSK that is
// published but signs nothing does not anchor the zone.
func TestChainAnchoredKeyDoesNotSignDNSKEY(t *testing.T) {

	data, _, zsk := signedZone(t)
	data.dnskeySigs = []dns.RR{zsk.sign(t, data.dnskey, time.Unix(2100000000, 0))}

	e, _, _ := chainExporter(t, data)

	if got := chainValue(t, e, "dnssec_chain_ds_match"); got != 0 {
		t.Fatalf("ds_match = %v, want 0", got)
	}

}

func TestChainExpiredSOASignature(t *testing.T) {

	data, _, zsk := signedZone(t)
	data.soaSigs = []dns.RR{zsk.sign(t, data.soa, time.Now().Add(-time.Minute))}

	e, _, _ := chainExporter(t, data)

	if got := chainValue(t, e, "dnssec_chain_soa_signature_valid"); got != 0 {
		t.Fatalf("soa_signature_valid = %v, want 0", got)
	}

	if got := chainValue(t, e, "dnssec_chain_ds_match"); got != 1 {
		t.Fatalf("ds_match = %v, want 1", got)
	}

}

// A signature made by a key that the zone does not publish must not count.
func TestChainSOASignedByUnpublishedKey(t *testing.T) {

	data, _, _ := signedZone(t)
	foreign := newChainKey(t, dns.ZONE)
	data.soaSigs = []dns.RR{foreign.sign(t, data.soa, time.Unix(2100000000, 0))}

	e, _, _ := chainExporter(t, data)

	if got := chainValue(t, e, "dnssec_chain_soa_signature_valid"); got != 0 {
		t.Fatalf("soa_signature_valid = %v, want 0", got)
	}

}

// A zone without a DS at the parent is signed but not anchored.
func TestChainNoDSAtParent(t *testing.T) {

	data, _, _ := signedZone(t)
	data.ds = nil

	e, _, _ := chainExporter(t, data)

	if got := chainValue(t, e, "dnssec_chain_ds_records"); got != 0 {
		t.Fatalf("ds_records = %v, want 0", got)
	}

	if got := chainValue(t, e, "dnssec_chain_ds_match"); got != 0 {
		t.Fatalf("ds_match = %v, want 0", got)
	}

}

// A server that refuses must report the failure and leave every other metric
// for it absent, so an alert cannot read a value that was never measured.
func TestChainServerRefuses(t *testing.T) {

	data, _, _ := signedZone(t)

	parent, stopParent := runChainServer(t, data, false)
	defer stopParent()

	server, stopServer := runChainServer(t, data, true)
	defer stopServer()

	e := NewDNSSECExporter(2*time.Second, []string{"127.0.0.1:53"}, nullLogger())
	e.Chains = []Chain{{Zone: "example.com", ParentServers: []string{parent}, Servers: []string{server}}}

	if err := e.Validate(); err != nil {
		t.Fatalf("expected a valid configuration, got: %v", err)
	}

	expected := `
# HELP dnssec_chain_ds_records Number of DS records for the zone at the parent
# TYPE dnssec_chain_ds_records gauge
dnssec_chain_ds_records{zone="example.com"} 1
# HELP dnssec_chain_query_success Did the server answer the queries for the chain check
# TYPE dnssec_chain_query_success gauge
dnssec_chain_query_success{server="` + parent + `",zone="example.com"} 1
dnssec_chain_query_success{server="` + server + `",zone="example.com"} 0
`

	if err := testutil.CollectAndCompare(e, strings.NewReader(expected)); err != nil {
		t.Fatalf("unexpected metrics: %v", err)
	}

}

// When no parent server answers, the DS set is unknown. The match must then be
// absent, not 0, or an outage at the parent would look like a broken chain.
func TestChainParentUnreachable(t *testing.T) {

	data, _, _ := signedZone(t)

	parent, stopParent := runChainServer(t, data, true)
	defer stopParent()

	server, stopServer := runChainServer(t, data, false)
	defer stopServer()

	e := NewDNSSECExporter(2*time.Second, []string{"127.0.0.1:53"}, nullLogger())
	e.Chains = []Chain{{Zone: "example.com", ParentServers: []string{parent}, Servers: []string{server}}}

	if err := e.Validate(); err != nil {
		t.Fatalf("expected a valid configuration, got: %v", err)
	}

	if count := testutil.CollectAndCount(e, "dnssec_chain_ds_match"); count != 0 {
		t.Fatalf("expected no ds_match series without a DS answer, got %d", count)
	}

	if count := testutil.CollectAndCount(e, "dnssec_chain_ds_records"); count != 0 {
		t.Fatalf("expected no ds_records series without a DS answer, got %d", count)
	}

	if got := chainValue(t, e, "dnssec_chain_soa_signature_valid"); got != 1 {
		t.Fatalf("soa_signature_valid = %v, want 1", got)
	}

}

func TestValidateChains(t *testing.T) {

	tests := []struct {
		name    string
		chains  []Chain
		wantErr string
	}{
		{
			name:   "valid chain",
			chains: []Chain{{Zone: "example.com", ParentServers: []string{"192.0.2.1:53"}, Servers: []string{"192.0.2.2:53"}}},
		},
		{
			name:    "chain without a zone",
			chains:  []Chain{{ParentServers: []string{"192.0.2.1:53"}, Servers: []string{"192.0.2.2:53"}}},
			wantErr: "a chain has no zone",
		},
		{
			name:    "chain without parent servers",
			chains:  []Chain{{Zone: "example.com", Servers: []string{"192.0.2.2:53"}}},
			wantErr: "parent_servers is required",
		},
		{
			name:    "chain without servers",
			chains:  []Chain{{Zone: "example.com", ParentServers: []string{"192.0.2.1:53"}}},
			wantErr: "servers is required",
		},
		{
			name:    "server without a port",
			chains:  []Chain{{Zone: "example.com", ParentServers: []string{"192.0.2.1"}, Servers: []string{"192.0.2.2:53"}}},
			wantErr: "needs a port",
		},
		{
			name: "duplicate chain",
			chains: []Chain{
				{Zone: "example.com", ParentServers: []string{"192.0.2.1:53"}, Servers: []string{"192.0.2.2:53"}},
				{Zone: "example.com.", ParentServers: []string{"192.0.2.1:53"}, Servers: []string{"192.0.2.2:53"}},
			},
			wantErr: "configured more than once",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			e := NewDNSSECExporter(time.Second, []string{"127.0.0.1:53"}, nullLogger())
			e.Chains = tt.chains

			err := e.Validate()

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected an error containing %q, got: %v", tt.wantErr, err)
			}

		})
	}

}
