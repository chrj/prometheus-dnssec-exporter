package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

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
