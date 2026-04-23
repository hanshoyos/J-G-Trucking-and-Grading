package gateway

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/http/httputil"
    "net/url"
    "time"

    "ace-api-gateway/internal/alerts"
    "ace-api-gateway/internal/config"

    "github.com/gin-gonic/gin"
    "go.uber.org/zap"
)

type Gateway struct {
    cfg    config.Config
    store  *alerts.Store
    log    *zap.Logger
    client *http.Client
}

func New(cfg config.Config, store *alerts.Store, log *zap.Logger) *Gateway {
    return &Gateway{
        cfg:   cfg,
        store: store,
        log:   log,
        client: &http.Client{Timeout: 10 * time.Second},
    }
}

func (g *Gateway) proxyTo(rawTarget string) gin.HandlerFunc {
    target, _ := url.Parse(rawTarget)
    proxy := httputil.NewSingleHostReverseProxy(target)
    proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
        w.WriteHeader(http.StatusBadGateway)
        fmt.Fprintf(w, `{"error":"upstream unavailable"}`)
    }
    return func(c *gin.Context) {
        c.Request.Host = target.Host
        proxy.ServeHTTP(c.Writer, c.Request)
    }
}

func (g *Gateway) RegisterRoutes(r *gin.Engine) {
    r.GET("/healthz", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    v1 := r.Group("/api/v1")
    v1.Use(corsMiddleware())

    // MITRE engine routes
    mitreProxy := g.proxyTo(g.cfg.MitreURL)
    v1.Any("/techniques", mitreProxy)
    v1.Any("/techniques/*path", mitreProxy)
    v1.Any("/tactics", mitreProxy)
    v1.Any("/tactics/*path", mitreProxy)
    v1.Any("/coverage", mitreProxy)
    v1.Any("/search", mitreProxy)

    // Threat intel routes
    intelProxy := g.proxyTo(g.cfg.ThreatIntelURL)
    v1.Any("/ioc", intelProxy)
    v1.Any("/ioc/*path", intelProxy)
    v1.Any("/feeds", intelProxy)
    v1.Any("/feeds/*path", intelProxy)

    // Asset inventory routes
    assetProxy := g.proxyTo(g.cfg.AssetInventoryURL)
    v1.Any("/assets", assetProxy)
    v1.Any("/assets/*path", assetProxy)

    // Alerts (served from in-memory Kafka consumer)
    v1.GET("/alerts", g.listAlerts)
    v1.GET("/alerts/stream", g.streamAlerts)

    // Aggregated summary
    v1.GET("/summary", g.summary)
}

func (g *Gateway) listAlerts(c *gin.Context) {
    recent := g.store.Recent()
    if recent == nil {
        recent = []json.RawMessage{}
    }
    c.JSON(200, recent)
}

func (g *Gateway) streamAlerts(c *gin.Context) {
    c.Header("Content-Type", "text/event-stream")
    c.Header("Cache-Control", "no-cache")
    c.Header("Connection", "keep-alive")
    c.Header("Access-Control-Allow-Origin", "*")

    ch := g.store.Subscribe()
    defer g.store.Unsubscribe(ch)

    // Flush buffered alerts first
    for _, msg := range g.store.Recent() {
        fmt.Fprintf(c.Writer, "data: %s\n\n", msg)
    }
    c.Writer.Flush()

    ctx := c.Request.Context()
    for {
        select {
        case <-ctx.Done():
            return
        case msg, ok := <-ch:
            if !ok {
                return
            }
            fmt.Fprintf(c.Writer, "data: %s\n\n", msg)
            c.Writer.Flush()
        }
    }
}

func (g *Gateway) summary(c *gin.Context) {
    type Summary struct {
        TotalAssets     int `json:"total_assets"`
        TotalAlerts     int `json:"total_alerts"`
        TotalTechniques int `json:"total_techniques"`
        ActiveFeeds     int `json:"active_feeds"`
    }

    // Fetch technique count
    techCount := g.fetchCount(g.cfg.MitreURL + "/api/v1/techniques?page_size=1")
    // Fetch asset count
    assetCount := g.fetchCount(g.cfg.AssetInventoryURL + "/api/v1/assets?page_size=1")

    c.JSON(200, Summary{
        TotalAssets:     assetCount,
        TotalAlerts:     len(g.store.Recent()),
        TotalTechniques: techCount,
        ActiveFeeds:     2, // CISA KEV + abuse.ch enabled by default
    })
}

func (g *Gateway) fetchCount(rawURL string) int {
    resp, err := g.client.Get(rawURL)
    if err != nil {
        return 0
    }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    var result map[string]interface{}
    if err := json.Unmarshal(body, &result); err != nil {
        return 0
    }
    if total, ok := result["total"].(float64); ok {
        return int(total)
    }
    return 0
}

func corsMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("Access-Control-Allow-Origin", "*")
        c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        c.Next()
    }
}
