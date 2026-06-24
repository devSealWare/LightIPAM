package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	// Embed the IANA timezone database in the binary so per-schedule scan windows
	// (Phase 6, ADR 0021) can resolve a schedule's window_tz via time.LoadLocation.
	// The app image is alpine, which ships no /usr/share/zoneinfo; embedding keeps
	// the lookup working without adding the tzdata OS package.
	_ "time/tzdata"

	"github.com/devSealWare/LightIPAM/internal/app"
	"github.com/devSealWare/LightIPAM/internal/config"
	"github.com/devSealWare/LightIPAM/internal/db"
	"github.com/devSealWare/LightIPAM/internal/scanner/dispatch"
	"github.com/devSealWare/LightIPAM/internal/scanner/orchestrator"
	"github.com/devSealWare/LightIPAM/internal/store"
)

// version is the build version, injected at build time via
// -ldflags "-X main.version=v1.0.0". It defaults to "dev" for local builds and
// is reported on /healthz and in the startup log so a running instance is
// identifiable.
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("light-ipam", version)
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("Light IPAM", "version", version)
	cfg := config.Load()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("connect database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		logger.Error("migrate database", "error", err)
		os.Exit(1)
	}

	var dispatcher orchestrator.Dispatcher
	if d, err := buildDispatcher(cfg); err != nil {
		logger.Warn("scanner dispatch disabled; scan jobs will fail until the app's mTLS client certificate is provided", "error", err)
	} else {
		dispatcher = d
		logger.Info("scanner dispatch enabled")
	}

	scanService := orchestrator.NewService(store.New(pool), dispatcher, logger)
	go scanService.StartScheduler(ctx, cfg.ScanSchedulerTick)
	scanService.StartAutoEnroll(ctx, cfg.ScannerAgentEndpoint)

	handler := app.New(app.Options{
		Config:  cfg,
		DB:      pool,
		Logger:  logger,
		Scans:   scanService,
		Version: version,
	})

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("starting server", "port", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown server", "error", err)
		os.Exit(1)
	}
}

// buildDispatcher loads the app's mTLS client certificate so it can act as the
// client to scanner agents. Missing files disable dispatch rather than failing
// startup, keeping the app usable without a configured agent.
func buildDispatcher(cfg config.Config) (*dispatch.Dispatcher, error) {
	cert, err := os.ReadFile(cfg.ScannerClientCert)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(cfg.ScannerClientKey)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(cfg.ScannerCACert)
	if err != nil {
		return nil, err
	}
	return dispatch.New(cert, key, ca)
}
