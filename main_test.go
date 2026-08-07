package main

import (
	"context"
	"crypto/ecdsa"
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
			name:    "no records",
			data:    "\n",
			wantErr: "no records configured",
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
