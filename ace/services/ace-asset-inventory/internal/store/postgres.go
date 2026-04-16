package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `
CREATE TABLE IF NOT EXISTS assets (
    asset_id         TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    hostname_or_ip   TEXT NOT NULL,
    ip_addresses     TEXT[],
    hostnames        TEXT[],
    macs             TEXT[],
    os_info          TEXT,
    asset_type       TEXT,
    domain           TEXT NOT NULL DEFAULT 'IT',
    purdue_level     INTEGER DEFAULT -1,
    cloud_provider   TEXT,
    cloud_region     TEXT,
    cloud_account_id TEXT,
    resource_arn     TEXT,
    tags             TEXT[],
    risk_score       DECIMAL(5,2) DEFAULT 0.0,
    first_seen       TIMESTAMPTZ NOT NULL,
    last_seen        TIMESTAMPTZ NOT NULL,
    last_updated     TIMESTAMPTZ DEFAULT NOW(),
    is_active        BOOLEAN DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_assets_tenant      ON assets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_key         ON assets(tenant_id, hostname_or_ip);
CREATE INDEX IF NOT EXISTS idx_assets_domain      ON assets(domain);
CREATE INDEX IF NOT EXISTS idx_assets_purdue      ON assets(purdue_level) WHERE purdue_level >= 0;
`

// Store provides CRUD operations for the assets table.
type Store struct {
	pool *pgxpool.Pool
}

// New connects to PostgreSQL and runs migrations.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return s, nil
}

// Close releases pool resources.
func (s *Store) Close() { s.pool.Close() }

// Ping checks database liveness.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// UpsertAsset inserts or updates an asset, updating last_seen and last_updated on conflict.
func (s *Store) UpsertAsset(ctx context.Context, a *Asset) error {
	const q = `
INSERT INTO assets
    (asset_id, tenant_id, hostname_or_ip, ip_addresses, hostnames, macs,
     os_info, asset_type, domain, purdue_level, cloud_provider, cloud_region,
     cloud_account_id, resource_arn, tags, risk_score, first_seen, last_seen,
     last_updated, is_active)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW(),TRUE)
ON CONFLICT (asset_id) DO UPDATE SET
    hostname_or_ip   = EXCLUDED.hostname_or_ip,
    ip_addresses     = EXCLUDED.ip_addresses,
    hostnames        = EXCLUDED.hostnames,
    os_info          = COALESCE(NULLIF(EXCLUDED.os_info,''), assets.os_info),
    asset_type       = COALESCE(NULLIF(EXCLUDED.asset_type,''), assets.asset_type),
    domain           = EXCLUDED.domain,
    purdue_level     = CASE WHEN EXCLUDED.purdue_level >= 0 THEN EXCLUDED.purdue_level
                            ELSE assets.purdue_level END,
    cloud_provider   = COALESCE(NULLIF(EXCLUDED.cloud_provider,''), assets.cloud_provider),
    cloud_region     = COALESCE(NULLIF(EXCLUDED.cloud_region,''), assets.cloud_region),
    cloud_account_id = COALESCE(NULLIF(EXCLUDED.cloud_account_id,''), assets.cloud_account_id),
    resource_arn     = COALESCE(NULLIF(EXCLUDED.resource_arn,''), assets.resource_arn),
    last_seen        = EXCLUDED.last_seen,
    last_updated     = NOW(),
    is_active        = TRUE`
	_, err := s.pool.Exec(ctx, q,
		a.AssetID, a.TenantID, a.HostnameOrIP, a.IPAddresses, a.Hostnames, a.MACs,
		a.OSInfo, a.AssetType, string(a.Domain), a.PurdueLevel,
		a.CloudProvider, a.CloudRegion, a.CloudAccountID, a.ResourceARN,
		a.Tags, a.RiskScore, a.FirstSeen, a.LastSeen,
	)
	return err
}

// GetAsset retrieves an asset by its ID.
func (s *Store) GetAsset(ctx context.Context, id string) (*Asset, error) {
	const q = `
SELECT asset_id, tenant_id, hostname_or_ip, ip_addresses, hostnames, macs,
       os_info, asset_type, domain, purdue_level, cloud_provider, cloud_region,
       cloud_account_id, resource_arn, tags, risk_score,
       first_seen, last_seen, last_updated, is_active
FROM assets WHERE asset_id = $1`
	return s.scanAsset(s.pool.QueryRow(ctx, q, id))
}

// ListAssets returns assets for a tenant, optionally filtered.
func (s *Store) ListAssets(ctx context.Context, tenantID, domain, assetType string) ([]Asset, error) {
	q := `
SELECT asset_id, tenant_id, hostname_or_ip, ip_addresses, hostnames, macs,
       os_info, asset_type, domain, purdue_level, cloud_provider, cloud_region,
       cloud_account_id, resource_arn, tags, risk_score,
       first_seen, last_seen, last_updated, is_active
FROM assets WHERE tenant_id = $1`
	args := []any{tenantID}

	if domain != "" {
		args = append(args, domain)
		q += fmt.Sprintf(" AND domain = $%d", len(args))
	}
	if assetType != "" {
		args = append(args, assetType)
		q += fmt.Sprintf(" AND asset_type = $%d", len(args))
	}
	q += " ORDER BY last_seen DESC LIMIT 1000"

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list: %w", err)
	}
	defer rows.Close()

	var out []Asset
	for rows.Next() {
		a, err := s.scanAssetRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// SearchAssets performs a hostname/IP keyword search within a tenant.
func (s *Store) SearchAssets(ctx context.Context, tenantID, keyword string) ([]Asset, error) {
	const q = `
SELECT asset_id, tenant_id, hostname_or_ip, ip_addresses, hostnames, macs,
       os_info, asset_type, domain, purdue_level, cloud_provider, cloud_region,
       cloud_account_id, resource_arn, tags, risk_score,
       first_seen, last_seen, last_updated, is_active
FROM assets
WHERE tenant_id = $1 AND (hostname_or_ip ILIKE $2 OR $2 = ANY(hostnames) OR $2 = ANY(ip_addresses))
ORDER BY last_seen DESC
LIMIT 200`
	rows, err := s.pool.Query(ctx, q, tenantID, "%"+keyword+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		a, err := s.scanAssetRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// GetByPurdueLevel returns OT assets at a specific Purdue level.
func (s *Store) GetByPurdueLevel(ctx context.Context, tenantID string, level int) ([]Asset, error) {
	const q = `
SELECT asset_id, tenant_id, hostname_or_ip, ip_addresses, hostnames, macs,
       os_info, asset_type, domain, purdue_level, cloud_provider, cloud_region,
       cloud_account_id, resource_arn, tags, risk_score,
       first_seen, last_seen, last_updated, is_active
FROM assets WHERE tenant_id = $1 AND purdue_level = $2 ORDER BY hostname_or_ip`
	rows, err := s.pool.Query(ctx, q, tenantID, level)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		a, err := s.scanAssetRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// UpdateRiskScore updates the risk score for an asset.
func (s *Store) UpdateRiskScore(ctx context.Context, assetID string, score float64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE assets SET risk_score = $1, last_updated = NOW() WHERE asset_id = $2`,
		score, assetID)
	return err
}

// FindByIP looks up an asset by exact IP address within a tenant.
func (s *Store) FindByIP(ctx context.Context, tenantID, ip string) (*Asset, error) {
	const q = `
SELECT asset_id, tenant_id, hostname_or_ip, ip_addresses, hostnames, macs,
       os_info, asset_type, domain, purdue_level, cloud_provider, cloud_region,
       cloud_account_id, resource_arn, tags, risk_score,
       first_seen, last_seen, last_updated, is_active
FROM assets WHERE tenant_id = $1 AND ($2 = ANY(ip_addresses) OR hostname_or_ip = $2)
LIMIT 1`
	return s.scanAsset(s.pool.QueryRow(ctx, q, tenantID, ip))
}

// ── Scan helpers ────────────────────────────────────────────────

type rowScanner interface{ Scan(...any) error }

func (s *Store) scanAsset(row rowScanner) (*Asset, error) {
	return scanAssetInto(row)
}

func (s *Store) scanAssetRow(rows interface{ Scan(...any) error }) (*Asset, error) {
	return scanAssetInto(rows)
}

func scanAssetInto(row interface{ Scan(...any) error }) (*Asset, error) {
	var a Asset
	var domain string
	var lastUpdated time.Time
	err := row.Scan(
		&a.AssetID, &a.TenantID, &a.HostnameOrIP,
		&a.IPAddresses, &a.Hostnames, &a.MACs,
		&a.OSInfo, &a.AssetType, &domain, &a.PurdueLevel,
		&a.CloudProvider, &a.CloudRegion, &a.CloudAccountID, &a.ResourceARN,
		&a.Tags, &a.RiskScore,
		&a.FirstSeen, &a.LastSeen, &lastUpdated, &a.IsActive,
	)
	if err != nil {
		return nil, fmt.Errorf("store: scan asset: %w", err)
	}
	a.Domain = AssetDomain(domain)
	a.LastUpdated = lastUpdated
	return &a, nil
}
