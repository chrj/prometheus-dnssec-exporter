// Command prometheus-dnssec-exporter checks DNSSEC signatures for configured
// records and exposes their validity and expiration as Prometheus metrics.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// shutdownTimeout is how long in-flight scrapes get to finish after a signal.
const shutdownTimeout = 10 * time.Second

// readHeaderTimeout bounds how long a client can take to send its headers.
const readHeaderTimeout = 10 * time.Second

func run(ctx context.Context, logger *slog.Logger) error {
	addr := flag.String("listen-address", ":9204", "Prometheus metrics port")
	conf := flag.String("config", "/etc/dnssec-checks", "Configuration file")
	resolvers := flag.String("resolvers", "8.8.8.8:53,1.1.1.1:53", "Resolvers to use (comma separated)")
	timeout := flag.Duration("timeout", 10*time.Second, "Timeout for network operations")

	flag.Parse()

	r, err := parseResolvers(*resolvers)
	if err != nil {
		return err
	}

	exporter, err := loadExporter(*conf, *timeout, r, logger)
	if err != nil {
		return err
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		exporter,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	// Buffered so the goroutine can always report and exit, even after shutdown.
	serveErr := make(chan error, 1)

	go func() {
		logger.Info("listening", "address", *addr, "records", len(exporter.Records), "resolvers", r)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve on %s: %w", *addr, err)
		}
		return nil

	case <-ctx.Done():
		logger.Info("shutting down", "timeout", shutdownTimeout)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down server: %w", err)
		}

		return nil
	}
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err := run(ctx, logger)
	stop()

	if err != nil {
		logger.Error("exporter failed", "error", err)
		os.Exit(1)
	}
}
