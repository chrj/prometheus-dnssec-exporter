package main

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

func (e *Exporter) resolve(ctx context.Context, rec Record, resolver string) (resolves bool, expires time.Time) {
	name := hostname(rec.Zone, rec.Record)

	msg := &dns.Msg{}
	msg.SetQuestion(name, dns.StringToType[rec.Type])
	msg.SetEdns0(4096, true)

	response, _, err := e.dnsClient.ExchangeContext(ctx, msg, resolver)
	if err != nil {
		e.logger.Error("resolving record failed",
			"name", name,
			"type", rec.Type,
			"zone", rec.Zone,
			"resolver", resolver,
			"error", err,
		)
		return
	}

	resolves = response.AuthenticatedData &&
		!response.CheckingDisabled &&
		response.Rcode == dns.RcodeSuccess

	// If multiple RRSIGs cover our record, return the one that expires earliest.
	for _, rr := range response.Answer {
		rrsig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}

		sigexp := time.Unix(int64(rrsig.Expiration), 0)
		if expires.IsZero() || sigexp.Before(expires) {
			expires = sigexp
		}
	}

	return
}

func hostname(zone, record string) string {
	if record == "@" {
		return dns.Fqdn(zone)
	}

	return dns.Fqdn(record + "." + zone)
}
