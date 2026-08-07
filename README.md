# DNSSEC Exporter for Prometheus

Check for validity and expiration in DNSSEC signatures and expose metrics for Prometheus

## Installation

    $ go install github.com/chrj/prometheus-dnssec-exporter@latest

## Usage

    Usage of prometheus-dnssec-exporter:
      -config string
        	Configuration file (default "/etc/dnssec-checks")
      -listen-address string
        	Prometheus metrics port (default ":9204")
      -resolvers string
        	Resolvers to use (comma separated) (default "8.8.8.8:53,1.1.1.1:53")
      -timeout duration
        	Timeout for network operations (default 10s)

You can give resolvers with or without a port. `8.8.8.8` and `8.8.8.8:53` are
equal.

The exporter reads its configuration file once at start. If the file is missing,
has a syntax error, or lists a record with an unknown type, the exporter stops
with an error.

The exporter stops on `SIGINT` or `SIGTERM`. Scrapes that are in progress get up
to 10 seconds to finish.

## Metrics

### Gauge: `dnssec_zone_record_days_left`

Number of days the signature will be valid.

Labels:

* `zone`
* `record`
* `type`

The exporter calculates this metric from the first resolver in the list. If more
than one RRSIG covers the record, this metric shows the days until the first
expiration.

If the resolver gives no answer, or the answer has no RRSIG, this metric is
absent. The exporter does not report a value that it cannot measure.

### Gauge: `dnssec_zone_record_earliest_rrsig_expiry`

Earliest expiring RRSIG covering the record on resolver in unixtime.

Labels:

* `resolver`
* `zone`
* `record`
* `type`

If more than one RRSIG covers the record, this metric shows the earliest
expiration.

The exporter reports this metric for every answer that has an RRSIG. It also
reports it when the resolver does not set the AD bit. Authoritative servers do
not validate, so you can point `-resolvers` at one and still monitor signature
expiration.

If the resolver gives no answer, or the answer has no RRSIG, this metric is
absent.

### Gauge: `dnssec_zone_transfer_success`

Did the zone transfer from the configured server succeed.

Labels:

* `server`
* `zone`

This metric is 1 only when the exporter transferred the whole zone. A refused
transfer, a wrong TSIG key, or a server that cannot be reached makes it 0.

The exporter reports this metric only for a `[[zones]]` entry.

### Gauge: `dnssec_zone_record_resolves`

Does the record resolve using the specified DNSSEC enabled resolvers.

Labels:

* `resolver`
* `zone`
* `record`
* `type`

This metric is 1 only when the record resolves **and** validates.

An authoritative server does not validate, so it never sets the AD bit. This
metric stays 0 when you use an authoritative server as a resolver.

### Examples

    # HELP dnssec_zone_record_days_left Number of days the signature will be valid
    # TYPE dnssec_zone_record_days_left gauge
    dnssec_zone_record_days_left{record="@",type="SOA",zone="ietf.org"} 320.3333333333333
    dnssec_zone_record_days_left{record="@",type="SOA",zone="verisigninc.com"} 9.333333333333334
    # HELP dnssec_zone_record_resolves Does the record resolve using the specified DNSSEC enabled resolvers
    # TYPE dnssec_zone_record_resolves gauge
    dnssec_zone_record_resolves{record="@",resolver="1.1.1.1:53",type="SOA",zone="ietf.org"} 1
    dnssec_zone_record_resolves{record="@",resolver="1.1.1.1:53",type="SOA",zone="verisigninc.com"} 1
    dnssec_zone_record_resolves{record="@",resolver="8.8.8.8:53",type="SOA",zone="ietf.org"} 1
    dnssec_zone_record_resolves{record="@",resolver="8.8.8.8:53",type="SOA",zone="verisigninc.com"} 1
    # HELP dnssec_zone_record_earliest_rrsig_expiry Earliest expiring RRSIG covering the record on resolver in unixtime
    # TYPE dnssec_zone_record_earliest_rrsig_expiry gauge
    dnssec_zone_record_earliest_rrsig_expiry{record="@",resolver="1.1.1.1:53",type="SOA",zone="ietf.org"} 1.664872679e+09
    dnssec_zone_record_earliest_rrsig_expiry{record="@",resolver="1.1.1.1:53",type="SOA",zone="verisigninc.com"} 1.664778306e+09
    dnssec_zone_record_earliest_rrsig_expiry{record="@",resolver="8.8.8.8:53",type="SOA",zone="ietf.org"} 1.664872679e+09
    dnssec_zone_record_earliest_rrsig_expiry{record="@",resolver="8.8.8.8:53",type="SOA",zone="verisigninc.com"} 1.664778306e+09

## Configuration

Supply a configuration file path with `-config` (optionally, defaults to `/etc/dnssec-checks`). Uses [TOML](https://github.com/toml-lang/toml).

[Sample configuration file](config.sample)

The exporter rejects a setting that it does not know, and names it in the error.
A misspelled setting is therefore an error at start, not a record that is
silently not checked.

### Records

A `[[records]]` entry checks one record against the resolvers given with
`-resolvers`. Use this to see what the public internet sees.

### Zones

A `[[zones]]` entry transfers a whole zone with AXFR and reports the record whose
signature expires first. Use this to find one expiring record among thousands,
which a per-record check cannot do.

    [[zones]]
      zone = "example.com"
      server = "ns1.example.com:53"
      key = "mysecretkey."

`server` is the server to transfer from. It defaults to the first `-resolvers`
entry. Give each zone its own server to check zones on your authoritative
servers and records on public resolvers in the same process.

`key` is optional. It names a `[[keys]]` entry that signs the transfer with TSIG.

### Keys

A `[[keys]]` entry holds a TSIG key. Get the secret from `tsig-keygen(1)`.

    [[keys]]
      name = "mysecretkey."
      algorithm = "hmac-sha256."
      secret = "mvgDxfYTSe8L+pp7h4r+PIeTc67YTPhGWZrhmIi2Rpo="

`algorithm` must be one of `hmac-sha1`, `hmac-sha224`, `hmac-sha256`,
`hmac-sha384` or `hmac-sha512`. HMAC-MD5 is not supported, because it is broken.

The exporter never writes a secret to its log. The configuration file holds the
secret in clear text, so give it the same protection as a private key.

## Prometheus target

Supply a listen address with `-listen-address` (optional, defaults to `:9204`), and configure a Prometheus job:

    - job_name: "dnssec"
      scrape_interval: "1m"
      static_configs:
        - targets:
            - "server:9204"

## Prometheus alert

The real benefit is an alert when a signature is near expiration, or is no longer
valid. See this [sample alert definition](dnssec.rules).

The sample alerts use a `for` window of 15 minutes. A shorter window pages on a
single failed scrape, because a temporary resolver failure makes the metric
absent.
