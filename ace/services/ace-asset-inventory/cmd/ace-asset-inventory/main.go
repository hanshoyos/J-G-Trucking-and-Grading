// ace-asset-inventory maintains a unified IT/OT/Cloud asset database.
// It passively discovers assets from the ace.events.normalized Kafka topic
// and exposes a REST API for asset queries and risk updates.
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

	"github.com/ace-platform/ace-asset-inventory/internal/api"
	"github.com/ace-platform/ace-asset-inventory/internal/config"
	"github.com/ace-platform/ace-asset-inventory/internal/discovery"
	"github.com/ace-platform/ace-asset-inventory/internal/purdue"
	"github.com/ace-platform/ace-asset-inventory/internal/store"
)

func main() {
	log, _ := zap.NewProduction()
	defer log.Sync() //nolint:errcheck

	cfg, err := config.Load()
	if err != nil {
		log.Fatal("failed to load config", zap.Error(err))
	}
	log.Info("ace-asset-inventory starting", zap.Int("port", cfg.Port))

	// ── Database ────────────────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal("database connection failed", zap.Error(err))
	}
	defer db.Close()
	log.Info("database connected and migrated")

	// ── Purdue classifier ────────────────────────────────────────
	clf := purdue.NewClassifier(purdue.Config{
		Level0Subnets: cfg.Purdue.Level0Subnets,
		Level1Subnets: cfg.Purdue.Level1Subnets,
		Level2Subnets: cfg.Purdue.Level2Subnets,
		Level3Subnets: cfg.Purdue.Level3Subnets,
	})

	// ── Passive discovery ────────────────────────────────────────
	disc, err := discovery.New(
		cfg.Kafka.Brokers,
		cfg.Kafka.NormalizedTopic,
		cfg.Kafka.ConsumerGroup,
		db, clf, log,
	)
	if err != nil {
		log.Fatal("failed to create passive discoverer", zap.Error(err))
	}

	discCtx, discCancel := context.WithCancel(context.Background())
	if disc != nil {
		go disc.Run(discCtx)
		log.Info("passive discovery consumer started",
			zap.String("topic", cfg.Kafka.NormalizedTopic))
	}

	// ── HTTP API ─────────────────────────────────────────────────
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	handler := api.NewHandler(db)
	handler.Register(r)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

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

	discCancel()

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Error("graceful shutdown error", zap.Error(err))
	}
	log.Info("ace-asset-inventory stopped")
}
