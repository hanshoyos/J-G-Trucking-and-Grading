// ace-mitre-engine ingests MITRE ATT&CK STIX 2.1 bundles (Enterprise v16 + ICS v3),
// stores techniques in PostgreSQL, and exposes a REST API for technique lookups
// and coverage heatmap generation.
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

	"github.com/ace-platform/ace-mitre-engine/internal/api"
	"github.com/ace-platform/ace-mitre-engine/internal/config"
	"github.com/ace-platform/ace-mitre-engine/internal/stix"
	"github.com/ace-platform/ace-mitre-engine/internal/store"
)

func main() {
	// ── Logger ──────────────────────────────────────────────────
	log, _ := zap.NewProduction()
	defer log.Sync() //nolint:errcheck

	// ── Config ──────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("failed to load config", zap.Error(err))
	}
	log.Info("ace-mitre-engine starting",
		zap.Int("port", cfg.Port),
		zap.Bool("sync_on_start", cfg.SyncOnStart),
		zap.Strings("frameworks", cfg.Frameworks),
	)

	// ── Database ────────────────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal("failed to connect to database", zap.Error(err))
	}
	defer db.Close()
	log.Info("database connected and migrated")

	// ── Optional startup sync ────────────────────────────────────
	if cfg.SyncOnStart {
		log.Info("syncing MITRE ATT&CK data on startup")
		syncCtx, syncCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		if err := syncFrameworks(syncCtx, log, db, cfg.Frameworks); err != nil {
			log.Error("startup MITRE sync failed (non-fatal)", zap.Error(err))
		}
		syncCancel()
	}

	// ── HTTP server ──────────────────────────────────────────────
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
		IdleTimeout:  60 * time.Second,
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
	log.Info("Shutting down")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Error("graceful shutdown error", zap.Error(err))
	}
	log.Info("ace-mitre-engine stopped")
}

// syncFrameworks fetches and upserts MITRE ATT&CK techniques for each framework.
func syncFrameworks(ctx context.Context, log *zap.Logger, db *store.Store, frameworks []string) error {
	urls := map[string]string{
		"enterprise": stix.EnterpriseURL,
		"ics":        stix.ICSAttackURL,
	}

	for _, fw := range frameworks {
		url, ok := urls[fw]
		if !ok {
			log.Warn("unknown framework, skipping", zap.String("framework", fw))
			continue
		}

		log.Info("fetching STIX bundle", zap.String("framework", fw), zap.String("url", url))
		patterns, err := stix.FetchAndParse(ctx, url)
		if err != nil {
			log.Error("failed to fetch/parse STIX bundle",
				zap.String("framework", fw), zap.Error(err))
			continue
		}

		techniques := make([]store.Technique, 0, len(patterns))
		for _, p := range patterns {
			if p.XMitreDeprecated {
				continue
			}
			tid := p.TechniqueID()
			if tid == "" {
				continue
			}

			parentID := ""
			if p.XMitreIsSubtechnique {
				// "T1078.004" → "T1078"
				parts := splitDot(tid)
				if len(parts) > 1 {
					parentID = parts[0]
				}
			}

			var refURL string
			for _, ref := range p.ExternalReferences {
				if ref.SourceName == stix.MitreSourceName {
					refURL = ref.URL
					break
				}
			}

			techniques = append(techniques, store.Technique{
				TechniqueID:    tid,
				Name:           p.Name,
				Description:    truncate(p.Description, 2000),
				Tactic:         p.PrimaryTactic(),
				Framework:      fw,
				IsSubtechnique: p.XMitreIsSubtechnique,
				ParentID:       parentID,
				Platforms:      p.XMitrePlatforms,
				DataSources:    p.XMitreDataSources,
				URL:            refURL,
			})
		}

		if err := db.BulkUpsert(ctx, techniques); err != nil {
			log.Error("bulk upsert failed",
				zap.String("framework", fw), zap.Error(err))
			continue
		}
		log.Info("MITRE sync complete",
			zap.String("framework", fw),
			zap.Int("techniques", len(techniques)))
	}
	return nil
}

func splitDot(s string) []string {
	var parts []string
	start := 0
	for i, c := range s {
		if c == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
