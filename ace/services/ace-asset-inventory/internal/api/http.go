// Package api implements the HTTP REST API for ace-asset-inventory.
package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/ace-platform/ace-asset-inventory/internal/store"
)

// Handler holds the store for HTTP handlers.
type Handler struct {
	db *store.Store
}

// NewHandler creates a Handler.
func NewHandler(db *store.Store) *Handler {
	return &Handler{db: db}
}

// Register mounts all routes on r.
func (h *Handler) Register(r *gin.Engine) {
	r.GET("/healthz", h.healthz)
	r.GET("/readyz",  h.readyz)

	v1 := r.Group("/api/v1")
	{
		v1.GET("/assets",              h.listAssets)
		v1.GET("/assets/search",       h.searchAssets)
		v1.GET("/assets/purdue",       h.assetsByPurdue)
		v1.GET("/assets/:id",          h.getAsset)
		v1.POST("/assets",             h.createOrUpdateAsset)
		v1.PUT("/assets/:id/risk",     h.updateRisk)
	}
}

// ── Health ──────────────────────────────────────────────────────

func (h *Handler) healthz(c *gin.Context) { c.String(http.StatusOK, "ok") }

func (h *Handler) readyz(c *gin.Context) {
	if err := h.db.Ping(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	c.String(http.StatusOK, "ok")
}

// ── Assets ──────────────────────────────────────────────────────

// listAssets handles GET /api/v1/assets?tenant=&domain=&type=
func (h *Handler) listAssets(c *gin.Context) {
	tenantID  := c.DefaultQuery("tenant", "default")
	domain    := c.Query("domain")
	assetType := c.Query("type")

	assets, err := h.db.ListAssets(c.Request.Context(), tenantID, domain, assetType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"count":  len(assets),
		"assets": assets,
	})
}

// getAsset handles GET /api/v1/assets/:id
func (h *Handler) getAsset(c *gin.Context) {
	a, err := h.db.GetAsset(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
		return
	}
	c.JSON(http.StatusOK, a)
}

// searchAssets handles GET /api/v1/assets/search?q=&tenant=
func (h *Handler) searchAssets(c *gin.Context) {
	q        := c.Query("q")
	tenantID := c.DefaultQuery("tenant", "default")
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "q parameter required"})
		return
	}
	results, err := h.db.SearchAssets(c.Request.Context(), tenantID, q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"count": len(results), "assets": results})
}

// assetsByPurdue handles GET /api/v1/assets/purdue?level=1&tenant=
func (h *Handler) assetsByPurdue(c *gin.Context) {
	tenantID := c.DefaultQuery("tenant", "default")
	levelStr := c.Query("level")

	// If level is omitted, return counts per level.
	if levelStr == "" {
		result := map[string]interface{}{}
		for lvl := 0; lvl <= 5; lvl++ {
			assets, err := h.db.GetByPurdueLevel(c.Request.Context(), tenantID, lvl)
			if err != nil {
				continue
			}
			result[strconv.Itoa(lvl)] = len(assets)
		}
		c.JSON(http.StatusOK, gin.H{"purdue_counts": result})
		return
	}

	level, err := strconv.Atoi(levelStr)
	if err != nil || level < -1 || level > 5 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "level must be -1 through 5"})
		return
	}
	assets, err := h.db.GetByPurdueLevel(c.Request.Context(), tenantID, level)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"purdue_level": level,
		"count":        len(assets),
		"assets":       assets,
	})
}

// createOrUpdateAsset handles POST /api/v1/assets (manual registration).
func (h *Handler) createOrUpdateAsset(c *gin.Context) {
	var a store.Asset
	if err := c.ShouldBindJSON(&a); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if a.AssetID == "" || a.TenantID == "" || a.HostnameOrIP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_id, tenant_id, hostname_or_ip are required"})
		return
	}
	if err := h.db.UpsertAsset(c.Request.Context(), &a); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "upserted", "asset_id": a.AssetID})
}

// updateRisk handles PUT /api/v1/assets/:id/risk?score=75.0
func (h *Handler) updateRisk(c *gin.Context) {
	id       := c.Param("id")
	scoreStr := c.Query("score")
	score, err := strconv.ParseFloat(scoreStr, 64)
	if err != nil || score < 0 || score > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "score must be a float 0–100"})
		return
	}
	if err := h.db.UpdateRiskScore(c.Request.Context(), id, score); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"asset_id": id, "risk_score": score})
}
