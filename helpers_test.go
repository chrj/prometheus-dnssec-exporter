package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func nullLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func soaRecord() Record {
	return Record{Zone: "example.org", Record: "@", Type: "SOA"}
}

// collectOne gathers the exporter and returns the single metric with the given
// name, so a test can read its value.
func collectOne(t *testing.T, e *Exporter, name string) prometheus.Gauge {

	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(e); err != nil {
		t.Fatalf("couldn't register exporter: %v", err)
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("couldn't gather metrics: %v", err)
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}

		if len(family.GetMetric()) != 1 {
			t.Fatalf("expected one %s series, got %d", name, len(family.GetMetric()))
		}

		g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "proxy"})
		g.Set(family.GetMetric()[0].GetGauge().GetValue())

		return g
	}

	t.Fatalf("metric %s was not reported", name)

	return nil

}
