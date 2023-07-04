# DNSSEC Exporter for Prometheus

Check for validity and expiration in DNSSEC signatures and expose metrics for Prometheus

## Installation

    $ go get -u github.com/chrj/prometheus-dnssec-exporter

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

## Metrics

### Gauge: `dnssec_zone_record_days_left`

Number of days the signature will be valid.

Labels:

* `zone`
* `record`
* `type`

If more than one resolver is configured, the metric will be calculated from the
resolver that is configured first.  If more than one RRSIG covers the record,
the number of days until the first one expires will be returned.  If the record
is not signed of the signature cannot be validated, this metric will contain a
bogus timestamp.

If a zone is monitored, this metric will be calculated for the earliest record
to expire in the zone.

### Gauge: `dnssec_zone_record_earliest_rrsig_expiry`

Earliest expiring RRSIG covering the record on resolver in unixtime.

Labels:

* `resolver`
* `zone`
* `record`
* `type`

If more than one RRSIG covers the record, the expiration time returned will be
of the one that expires earliest.  If the record does not resolve or cannot be
validated, this metric will be absent.

If a zone is monitored, this metric will be calculated for the earliest record
to expire in the zone.

### Gauge: `dnssec_zone_record_resolves`

Does the record resolve using the specified DNSSEC enabled resolvers.

Labels:

* `resolver`
* `zone`
* `record`
* `type`

This metric will return 1 only if the record resolves **and** validates.

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

### Support for authoritative servers (AXFR)

If `[[zones]]` are configured, the resolvers specified with `-resolvers` must be configured to accept zone transfers (AXFR queries), optionally secured with a TSIG key, from the machine running prometheus-dnssec-exporter.  Recursive resolvers do not support zone transfers.

If a TSIG `key` is configured for a zone, a matching `[[keys]]` configuration must exist.

It is considered impolite to send AXFR queries to public resolvers (e.g. Cloudflare, Google, Quad9).

Run separate instances of prometheus-dnssec-exporter to monitor zones on authoritative servers as well as records on public resolvers.

## Prometheus target

Supply a listen address with `-addr` (optionally, defaults to `:9204`), and configure a Prometheus job:

    - job_name: "dnssec"
      scrape_interval: "1m"
      static_configs:
        - targets:
            - "server:9204"

## Prometheus alert

The real benefit is getting an alert triggered when a signature is nearing expiration or is not longer valid. Check this [sample alert definition](dnssec.rules).
