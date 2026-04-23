package main

import (
    "context"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "ace-api-gateway/internal/alerts"
    "ace-api-gateway/internal/config"
    "ace-api-gateway/internal/gateway"

    "github.com/gin-gonic/gin"
    "go.uber.org/zap"
)

func main() {
    log, _ := zap.NewProduction()
    defer log.Sync()

    cfg := config.Load()

    store := alerts.NewStore(log)

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    go store.ConsumeLoop(ctx, cfg.KafkaBrokers, cfg.AlertsTopic)

    gin.SetMode(gin.ReleaseMode)
    r := gin.New()
    r.Use(gin.Recovery())

    gw := gateway.New(cfg, store, log)
    gw.RegisterRoutes(r)

    srv := &http.Server{
        Addr:    ":" + cfg.Port,
        Handler: r,
    }

    go func() {
        log.Info("ace-api-gateway listening", zap.String("port", cfg.Port))
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatal("server error", zap.Error(err))
        }
    }()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    cancel()
    shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer shutCancel()
    srv.Shutdown(shutCtx)
    log.Info("ace-api-gateway stopped")
}
