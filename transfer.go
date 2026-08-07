package main

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// tsigFudge is the time difference in seconds that a TSIG signature tolerates
// between the two clocks. 300 is the value that BIND and Knot use.
const tsigFudge = 300

// signature is the RRSIG in a zone that expires first, and the record it covers.
type signature struct {
	record     string
	recordType string
	expires    time.Time
}

// transfer reads a whole zone over AXFR and returns the signature that expires
// first. The caller decides what an error means for the metrics.
func (e *Exporter) transfer(ctx context.Context, zone Zone, server string) (signature, error) {
	var earliest signature

	msg := &dns.Msg{}
	msg.SetAxfr(dns.Fqdn(zone.Zone))

	tr := &dns.Transfer{
		DialTimeout:  e.timeout,
		ReadTimeout:  e.timeout,
		WriteTimeout: e.timeout,
	}

	if zone.Key != "" {
		key := e.keys[dns.Fqdn(zone.Key)]

		tr.TsigSecret = map[string]string{key.Name: key.Secret}
		msg.SetTsig(key.Name, key.Algorithm, tsigFudge, time.Now().Unix())
	}

	envelopes, err := tr.In(msg, server)
	if err != nil {
		return earliest, fmt.Errorf("start transfer: %w", err)
	}

	// The channel must be drained to the end, or the reading goroutine inside
	// the library never stops. Record the first error and keep reading.
	var transferErr error

	for envelope := range envelopes {
		if envelope.Error != nil {
			if transferErr == nil {
				transferErr = envelope.Error
			}

			continue
		}

		if ctx.Err() != nil {
			if transferErr == nil {
				transferErr = ctx.Err()
			}

			continue
		}

		for _, rr := range envelope.RR {
			rrsig, ok := rr.(*dns.RRSIG)
			if !ok {
				continue
			}

			expires := time.Unix(int64(rrsig.Expiration), 0)
			if !earliest.expires.IsZero() && !expires.Before(earliest.expires) {
				continue
			}

			earliest = signature{
				record:     rrsig.Hdr.Name,
				recordType: dns.TypeToString[rrsig.TypeCovered],
				expires:    expires,
			}
		}
	}

	if transferErr != nil {
		return signature{}, fmt.Errorf("read zone: %w", transferErr)
	}

	return earliest, nil
}
