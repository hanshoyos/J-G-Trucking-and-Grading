// ace-threat-intel aggregates IOCs from CISA KEV, AlienVault OTX, abuse.ch
// (URLhaus + MalwareBazaar), and STIX/TAXII 2.1 feeds.  IOCs are stored in
// Redis for fast lookup by the ace-correlate engine.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/ace-platform/ace-threat-intel/internal/api"
	"github.com/ace-platform/ace-threat-intel/internal/config"
	"github.com/ace-platform/ace-threat-intel/internal/feeds"
	"github.com/ace-platform/ace-threat-intel/internal/ioc"
)

func main() {
	log, _ := zap.NewProduction()
	defer log.Sync() //nolint:errcheck

	cfg, err := config.Load()
	if err != nil {
		log.Fatal("failed to load config", zap.Error(err))
	}
	log.Info("ace-threat-intel starting",
		zap.Int("port", cfg.Port),
		zap.Duration("sync_interval", cfg.SyncInterval),
	)

	// ── Redis ────────────────────────────────────────────────────
	cache := ioc.New(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB, cfg.IOCCacheTTL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cache.Ping(ctx); err != nil {
		log.Fatal("failed to connect to Redis", zap.Error(err))
	}
	defer cache.Close() //nolint:errcheck
	log.Info("Redis connected")

	// ── Build feed list ──────────────────────────────────────────
	allFeeds := []feeds.Feed{
		feeds.NewCISAKEVFeed(),
		feeds.NewURLhausFeed(),
		feeds.NewMalwareBazaarFeed(),
	}
	if cfg.OTXAPIKey != "" {
		allFeeds = append(allFeeds, feeds.NewOTXFeed(cfg.OTXAPIKey))
	}
	if cfg.TAXIIServer != "" {
		allFeeds = append(allFeeds, feeds.NewTAXIIFeed(
			cfg.TAXIIServer, "default", cfg.TAXIIUser, cfg.TAXIIPass,
		))
	}
	log.Info("feeds configured", zap.Int("count", len(allFeeds)))

	// ── HTTP API ─────────────────────────────────────────────────
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	handler := api.NewHandler(cache, allFeeds)
	handler.Register(r)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// ── Periodic feed sync ───────────────────────────────────────
	go func() {
		log.Info("running initial feed sync")
		handler.RunSync()

		ticker := time.NewTicker(cfg.SyncInterval)
		defer ticker.Stop()
		for range ticker.C {
			log.Info("running scheduled feed sync")
			handler.RunSync()
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Info("HTTP server listening", zap.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("HTTP server error", zap.Error(err))
		}
	}()

	<-quit
	log.Info("shutting down")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Error("graceful shutdown error", zap.Error(err))
	}
	log.Info("ace-threat-intel stopped")
}
