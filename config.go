package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
)

// defaultDNSPort is applied to resolvers that are configured without a port.
const defaultDNSPort = "53"

// Record is one entry from the configuration file.
type Record struct {
	Zone   string
	Record string
	Type   string
}

// String returns the record in a form that identifies it in logs and errors.
func (r Record) String() string {
	return fmt.Sprintf("%s %s in %s", r.Record, r.Type, r.Zone)
}

// Zone is one entry from the [[zones]] table. The exporter transfers the whole
// zone and reports the record whose signature expires first.
type Zone struct {
	Zone   string
	Server string
	Key    string
}

// Key is one entry from the [[keys]] table. It is a TSIG key that authenticates
// a zone transfer.
type Key struct {
	Name      string
	Algorithm string
	Secret    string
}

// LogValue keeps the secret out of the logs. Without it, a log call that takes
// the whole key writes the shared secret to the log file.
func (k Key) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", k.Name),
		slog.String("algorithm", k.Algorithm),
	)
}

// String keeps the secret out of error messages, for the same reason.
func (k Key) String() string {
	return fmt.Sprintf("%s (%s)", k.Name, k.Algorithm)
}

// Validate reports configuration problems that would otherwise show up as
// missing or duplicated metrics at scrape time.
func (e *Exporter) Validate() error {
	if len(e.Records) == 0 && len(e.Zones) == 0 {
		return errors.New("nothing configured to check: add at least one [[records]] or [[zones]] section")
	}

	if err := e.validateKeys(); err != nil {
		return err
	}

	if err := e.validateZones(); err != nil {
		return err
	}

	seen := make(map[Record]bool, len(e.Records))

	for _, rec := range e.Records {
		if rec.Zone == "" {
			return fmt.Errorf("record %q: zone is required", rec.Record)
		}

		if rec.Record == "" {
			return fmt.Errorf("zone %q: record is required, use \"@\" for the zone apex", rec.Zone)
		}

		if _, ok := dns.StringToType[rec.Type]; !ok {
			return fmt.Errorf("record %s in zone %s: unknown type %q, use a DNS type such as SOA, A or MX", rec.Record, rec.Zone, rec.Type)
		}

		if seen[rec] {
			return fmt.Errorf("record %s is configured more than once, remove the duplicate", rec)
		}

		seen[rec] = true
	}

	return nil
}

// validateKeys checks the [[keys]] table and indexes it by key name.
func (e *Exporter) validateKeys() error {
	e.keys = make(map[string]Key, len(e.Keys))

	for _, key := range e.Keys {
		if key.Name == "" {
			return errors.New("a key has no name: give every [[keys]] entry a name")
		}

		if key.Secret == "" {
			return fmt.Errorf("key %s has no secret: give it the base64 secret from tsig-keygen", key.Name)
		}

		// miekg/dns matches the key name and algorithm in canonical form, so a
		// name written without the trailing dot never matches the answer.
		name := dns.Fqdn(key.Name)
		algorithm := dns.Fqdn(key.Algorithm)

		if !tsigAlgorithms[algorithm] {
			return fmt.Errorf("key %s has unknown algorithm %q, use one of %s",
				key.Name, key.Algorithm, strings.Join(tsigAlgorithmNames(), ", "))
		}

		if _, ok := e.keys[name]; ok {
			return fmt.Errorf("key %s is configured more than once, remove the duplicate", key.Name)
		}

		e.keys[name] = Key{Name: name, Algorithm: algorithm, Secret: key.Secret}
	}

	return nil
}

// validateZones checks the [[zones]] table against the configured keys.
func (e *Exporter) validateZones() error {
	seen := make(map[string]bool, len(e.Zones))

	for _, zone := range e.Zones {
		if zone.Zone == "" {
			return errors.New("a zone has no name: give every [[zones]] entry a zone")
		}

		if zone.Key != "" {
			if _, ok := e.keys[dns.Fqdn(zone.Key)]; !ok {
				return fmt.Errorf("zone %s uses key %q, which no [[keys]] section defines", zone.Zone, zone.Key)
			}
		}

		if zone.Server != "" {
			if _, _, err := net.SplitHostPort(zone.Server); err != nil {
				return fmt.Errorf("zone %s: server %q needs a port, for example %q",
					zone.Zone, zone.Server, net.JoinHostPort(zone.Server, defaultDNSPort))
			}
		}

		name := dns.Fqdn(zone.Zone)
		if seen[name] {
			return fmt.Errorf("zone %s is configured more than once, remove the duplicate", zone.Zone)
		}

		seen[name] = true
	}

	return nil
}

// tsigAlgorithms are the TSIG algorithms that miekg/dns still supports. HMAC-MD5
// is left out on purpose, because it is broken and the library rejects it.
var tsigAlgorithms = map[string]bool{
	dns.HmacSHA1:   true,
	dns.HmacSHA224: true,
	dns.HmacSHA256: true,
	dns.HmacSHA384: true,
	dns.HmacSHA512: true,
}

func tsigAlgorithmNames() []string {
	names := make([]string, 0, len(tsigAlgorithms))
	for name := range tsigAlgorithms {
		names = append(names, name)
	}

	slices.Sort(names)

	return names
}

// parseResolvers splits a comma separated resolver list and applies the default
// DNS port to entries that do not carry one.
func parseResolvers(list string) ([]string, error) {
	var resolvers []string

	for entry := range strings.SplitSeq(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if _, _, err := net.SplitHostPort(entry); err != nil {
			entry = net.JoinHostPort(entry, defaultDNSPort)
		}

		resolvers = append(resolvers, entry)
	}

	if len(resolvers) == 0 {
		return nil, errors.New("no resolvers configured: pass at least one address to -resolvers")
	}

	return resolvers, nil
}

// config is the schema of the configuration file.
type config struct {
	Records []Record
	Zones   []Zone
	Keys    []Key
}

// loadExporter reads the configuration file and returns a validated exporter.
func loadExporter(path string, timeout time.Duration, resolvers []string, logger *slog.Logger) (*Exporter, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configuration file %s: %w", path, err)
	}
	// The file is only read, so a failure to close it cannot lose data.
	defer func() { _ = f.Close() }()

	var cfg config

	md, err := toml.NewDecoder(f).Decode(&cfg)
	if err != nil {
		return nil, fmt.Errorf("parse configuration file %s: %w", path, err)
	}

	// A misspelled key must stop the exporter. Left unreported, it reads as a
	// setting that was accepted, while the record is silently not checked.
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}

		return nil, fmt.Errorf("configuration file %s has unknown keys: %s", path, strings.Join(keys, ", "))
	}

	exporter := NewDNSSECExporter(timeout, resolvers, logger)
	exporter.Records = cfg.Records
	exporter.Zones = cfg.Zones
	exporter.Keys = cfg.Keys

	if err := exporter.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration file %s: %w", path, err)
	}

	return exporter, nil
}
