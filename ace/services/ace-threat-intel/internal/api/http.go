// Package api implements the HTTP REST API for ace-threat-intel.
package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ace-platform/ace-threat-intel/internal/feeds"
	"github.com/ace-platform/ace-threat-intel/internal/ioc"
)

// Handler holds the dependencies for all HTTP handlers.
type Handler struct {
	cache        *ioc.Cache
	allFeeds     []feeds.Feed
	statusMu     sync.RWMutex
	feedStatuses map[string]feeds.FeedStatus
}

// NewHandler creates a Handler.
func NewHandler(cache *ioc.Cache, allFeeds []feeds.Feed) *Handler {
	statuses := make(map[string]feeds.FeedStatus, len(allFeeds))
	for _, f := range allFeeds {
		statuses[f.Name()] = feeds.FeedStatus{Name: f.Name()}
	}
	return &Handler{
		cache:        cache,
		allFeeds:     allFeeds,
		feedStatuses: statuses,
	}
}

// Register mounts all routes on r.
func (h *Handler) Register(r *gin.Engine) {
	r.GET("/healthz", h.healthz)
	r.GET("/readyz",  h.readyz)

	v1 := r.Group("/api/v1")
	{
		v1.GET("/ioc/lookup",      h.lookupIOC)
		v1.POST("/ioc/bulk-lookup", h.bulkLookup)
		v1.GET("/feeds/status",    h.feedsStatus)
		v1.POST("/feeds/sync",     h.syncFeeds)
	}
}

// ── Health ──────────────────────────────────────────────────────

func (h *Handler) healthz(c *gin.Context) { c.String(http.StatusOK, "ok") }

func (h *Handler) readyz(c *gin.Context) {
	if err := h.cache.Ping(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "redis unavailable"})
		return
	}
	c.String(http.StatusOK, "ok")
}

// ── IOC lookup ──────────────────────────────────────────────────

// lookupIOC handles GET /api/v1/ioc/lookup?type=ip&value=1.2.3.4
func (h *Handler) lookupIOC(c *gin.Context) {
	iocType := feeds.IOCType(strings.ToLower(c.Query("type")))
	value := c.Query("value")
	if iocType == "" || value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type and value parameters are required"})
		return
	}

	result, err := h.cache.Lookup(c.Request.Context(), iocType, value)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if result == nil {
		c.JSON(http.StatusNotFound, gin.H{"found": false, "type": iocType, "value": value})
		return
	}
	c.JSON(http.StatusOK, gin.H{"found": true, "ioc": result})
}

// BulkLookupRequest is the JSON body for POST /api/v1/ioc/bulk-lookup.
type BulkLookupRequest struct {
	IOCs []ioc.LookupRequest `json:"iocs"`
}

// bulkLookup handles POST /api/v1/ioc/bulk-lookup.
func (h *Handler) bulkLookup(c *gin.Context) {
	var req BulkLookupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.IOCs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "iocs array must not be empty"})
		return
	}
	if len(req.IOCs) > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "maximum 500 IOCs per request"})
		return
	}

	results, err := h.cache.BulkLookup(c.Request.Context(), req.IOCs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"count":   len(results),
		"results": results,
	})
}

// ── Feed management ─────────────────────────────────────────────

func (h *Handler) feedsStatus(c *gin.Context) {
	h.statusMu.RLock()
	defer h.statusMu.RUnlock()
	statuses := make([]feeds.FeedStatus, 0, len(h.feedStatuses))
	for _, s := range h.feedStatuses {
		statuses = append(statuses, s)
	}
	c.JSON(http.StatusOK, gin.H{"feeds": statuses})
}

// syncFeeds triggers a manual feed sync in the background.
func (h *Handler) syncFeeds(c *gin.Context) {
	go h.RunSync()
	c.JSON(http.StatusAccepted, gin.H{"status": "sync started"})
}

// RunSync runs all feeds and stores the resulting IOCs.
// Intended to be called periodically and on demand.
func (h *Handler) RunSync() {
	ctx2 := context.Background()
	for _, f := range h.allFeeds {
		start := time.Now()
		iocs, err := f.FetchIOCs(ctx2)

		status := feeds.FeedStatus{
			Name:     f.Name(),
			LastSync: time.Now().UTC(),
		}
		if err != nil {
			status.Error = err.Error()
		} else {
			status.IOCsAdded = len(iocs)
			if storeErr := h.cache.Store(ctx2, iocs); storeErr != nil {
				status.Error = storeErr.Error()
			}
		}

		h.statusMu.Lock()
		h.feedStatuses[f.Name()] = status
		h.statusMu.Unlock()

		_ = start
	}
}
