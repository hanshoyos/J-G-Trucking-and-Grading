// Package ioc provides the Redis-backed IOC cache used by ace-threat-intel.
package ioc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ace-platform/ace-threat-intel/internal/feeds"
)

const keyPrefix = "ace:ioc:"

// Cache is a Redis-backed store for IOC lookups.
type Cache struct {
	rdb *redis.Client
	ttl time.Duration
}

// New creates a Cache connected to the given Redis address.
func New(addr, password string, db int, ttl time.Duration) *Cache {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &Cache{rdb: rdb, ttl: ttl}
}

// Ping checks Redis connectivity.
func (c *Cache) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// Close releases the Redis client.
func (c *Cache) Close() error { return c.rdb.Close() }

// cacheKey builds the Redis key for a given IOC type + value.
func cacheKey(iocType feeds.IOCType, value string) string {
	return fmt.Sprintf("%s%s:%s", keyPrefix, iocType, value)
}

// Store persists a slice of IOCs in Redis.
func (c *Cache) Store(ctx context.Context, iocs []feeds.IOC) error {
	pipe := c.rdb.Pipeline()
	for _, ioc := range iocs {
		data, err := json.Marshal(ioc)
		if err != nil {
			continue
		}
		pipe.Set(ctx, cacheKey(ioc.Type, ioc.Value), data, c.ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// Lookup retrieves a single IOC by type and value.
// Returns nil (no error) if the IOC is not cached.
func (c *Cache) Lookup(ctx context.Context, iocType feeds.IOCType, value string) (*feeds.IOC, error) {
	data, err := c.rdb.Get(ctx, cacheKey(iocType, value)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ioc: lookup: %w", err)
	}
	var ioc feeds.IOC
	if err := json.Unmarshal(data, &ioc); err != nil {
		return nil, fmt.Errorf("ioc: unmarshal: %w", err)
	}
	return &ioc, nil
}

// LookupRequest is a single IOC lookup request for bulk operations.
type LookupRequest struct {
	Type  feeds.IOCType `json:"type"`
	Value string        `json:"value"`
}

// BulkLookup resolves multiple IOCs in a single pipelined Redis call.
// Returns a map from "type:value" → *IOC (nil for misses).
func (c *Cache) BulkLookup(ctx context.Context, requests []LookupRequest) (map[string]*feeds.IOC, error) {
	if len(requests) == 0 {
		return nil, nil
	}

	keys := make([]string, len(requests))
	for i, req := range requests {
		keys[i] = cacheKey(req.Type, req.Value)
	}

	results, err := c.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("ioc: bulk lookup: %w", err)
	}

	out := make(map[string]*feeds.IOC, len(requests))
	for i, req := range requests {
		mapKey := string(req.Type) + ":" + req.Value
		if results[i] == nil {
			out[mapKey] = nil
			continue
		}
		raw, ok := results[i].(string)
		if !ok {
			continue
		}
		var ioc feeds.IOC
		if err := json.Unmarshal([]byte(raw), &ioc); err == nil {
			out[mapKey] = &ioc
		}
	}
	return out, nil
}
