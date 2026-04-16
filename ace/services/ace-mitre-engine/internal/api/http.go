// Package api implements the HTTP REST API for ace-mitre-engine.
package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/ace-platform/ace-mitre-engine/internal/heatmap"
	"github.com/ace-platform/ace-mitre-engine/internal/store"
)

// Handler bundles the dependencies for all HTTP handlers.
type Handler struct {
	store *store.Store
}

// NewHandler creates a new Handler.
func NewHandler(s *store.Store) *Handler {
	return &Handler{store: s}
}

// Register mounts all routes on r.
func (h *Handler) Register(r *gin.Engine) {
	r.GET("/healthz", h.healthz)
	r.GET("/readyz",  h.readyz)

	v1 := r.Group("/api/v1")
	{
		v1.GET("/techniques",     h.listTechniques)
		v1.GET("/techniques/:id", h.getTechnique)
		v1.GET("/tactics",        h.listTactics)
		v1.GET("/coverage",       h.getCoverage)
		v1.POST("/seen/:id",      h.markSeen)
		v1.GET("/search",         h.searchTechniques)
	}
}

// ── Health ──────────────────────────────────────────────────────

func (h *Handler) healthz(c *gin.Context) {
	c.String(http.StatusOK, "ok")
}

func (h *Handler) readyz(c *gin.Context) {
	ctx := c.Request.Context()
	if err := h.store.Ping(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	c.String(http.StatusOK, "ok")
}

// ── Techniques ──────────────────────────────────────────────────

// listTechniques returns all techniques, optionally filtered by ?framework=.
func (h *Handler) listTechniques(c *gin.Context) {
	ctx := c.Request.Context()
	framework := c.Query("framework")

	var (
		techniques []store.Technique
		err        error
	)
	if framework == "" {
		techniques, err = h.store.ListAll(ctx)
	} else {
		techniques, err = h.store.ListByFramework(ctx, strings.ToLower(framework))
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"count":      len(techniques),
		"techniques": techniques,
	})
}

// getTechnique returns a single technique by ID (e.g. T1078).
func (h *Handler) getTechnique(c *gin.Context) {
	id := strings.ToUpper(c.Param("id"))
	t, err := h.store.GetTechnique(context.Background(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "technique not found"})
		return
	}
	c.JSON(http.StatusOK, t)
}

// listTactics returns the distinct tactic names.
func (h *Handler) listTactics(c *gin.Context) {
	techniques, err := h.store.ListAll(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	seen := map[string]bool{}
	var tactics []string
	for _, t := range techniques {
		if t.Tactic != "" && !seen[t.Tactic] {
			seen[t.Tactic] = true
			tactics = append(tactics, t.Tactic)
		}
	}
	c.JSON(http.StatusOK, gin.H{"tactics": tactics})
}

// getCoverage returns a MITRE Navigator-compatible heatmap layer.
func (h *Handler) getCoverage(c *gin.Context) {
	ctx := c.Request.Context()
	coverage, err := h.store.GetCoverage(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	domain := c.DefaultQuery("framework", "enterprise")
	if domain == "enterprise" {
		domain = "enterprise-attack"
	} else if domain == "ics" {
		domain = "ics-attack"
	}

	layer := heatmap.Generate(coverage, domain)
	c.JSON(http.StatusOK, layer)
}

// markSeen increments the seen counter for a technique.
func (h *Handler) markSeen(c *gin.Context) {
	id := strings.ToUpper(c.Param("id"))
	if err := h.store.MarkSeen(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"technique_id": id, "status": "marked"})
}

// searchTechniques performs a keyword search.
func (h *Handler) searchTechniques(c *gin.Context) {
	q := c.Query("q")
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "q parameter required"})
		return
	}
	results, err := h.store.SearchTechniques(c.Request.Context(), q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"query":      q,
		"count":      len(results),
		"techniques": results,
	})
}
