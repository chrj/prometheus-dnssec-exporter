package main

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

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
