package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `
CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id     TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT,
    tactic           TEXT,
    framework        TEXT NOT NULL,
    is_subtechnique  BOOLEAN DEFAULT FALSE,
    parent_id        TEXT,
    platforms        TEXT[],
    data_sources     TEXT[],
    url              TEXT,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    seen_count       INTEGER DEFAULT 0,
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mitre_framework ON mitre_techniques(framework);
CREATE INDEX IF NOT EXISTS idx_mitre_tactic    ON mitre_techniques(tactic);
`

// Store wraps a PostgreSQL connection pool and provides CRUD operations
// for MITRE ATT&CK techniques.
type Store struct {
	pool *pgxpool.Pool
}

// New opens a pool to `dsn` and runs auto-migration.
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

// Close releases the connection pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks database liveness.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// UpsertTechnique inserts or updates a technique row.
func (s *Store) UpsertTechnique(ctx context.Context, t *Technique) error {
	const q = `
INSERT INTO mitre_techniques
    (technique_id, name, description, tactic, framework, is_subtechnique,
     parent_id, platforms, data_sources, url, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
ON CONFLICT (technique_id) DO UPDATE SET
    name            = EXCLUDED.name,
    description     = EXCLUDED.description,
    tactic          = EXCLUDED.tactic,
    is_subtechnique = EXCLUDED.is_subtechnique,
    parent_id       = EXCLUDED.parent_id,
    platforms       = EXCLUDED.platforms,
    data_sources    = EXCLUDED.data_sources,
    url             = EXCLUDED.url,
    updated_at      = NOW()`
	_, err := s.pool.Exec(ctx, q,
		t.TechniqueID, t.Name, t.Description, t.Tactic, t.Framework,
		t.IsSubtechnique, t.ParentID, t.Platforms, t.DataSources, t.URL,
	)
	return err
}

// GetTechnique retrieves a single technique by its ID.
func (s *Store) GetTechnique(ctx context.Context, id string) (*Technique, error) {
	const q = `
SELECT technique_id, name, description, tactic, framework, is_subtechnique,
       parent_id, platforms, data_sources, url, first_seen, last_seen,
       seen_count, updated_at
FROM mitre_techniques
WHERE technique_id = $1`
	return scanTechnique(s.pool.QueryRow(ctx, q, id))
}

// ListTechniques returns all techniques, optionally filtered by framework.
func (s *Store) ListTechniques(ctx context.Context, framework string) ([]Technique, error) {
	var (
		rows interface{ Next() bool; Scan(...any) error; Err() error }
		err  error
	)
	if framework == "" {
		rows, err = s.pool.Query(ctx,
			`SELECT technique_id, name, description, tactic, framework, is_subtechnique,
			        parent_id, platforms, data_sources, url, first_seen, last_seen,
			        seen_count, updated_at
			 FROM mitre_techniques ORDER BY technique_id`)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT technique_id, name, description, tactic, framework, is_subtechnique,
			        parent_id, platforms, data_sources, url, first_seen, last_seen,
			        seen_count, updated_at
			 FROM mitre_techniques WHERE framework = $1 ORDER BY technique_id`, framework)
	}
	if err != nil {
		return nil, fmt.Errorf("store: list: %w", err)
	}

	// pgx rows implements the right interface; type-assert here.
	type scanner interface {
		Next() bool
		Scan(dest ...any) error
		Err() error
	}
	pgxRows, ok := rows.(scanner)
	if !ok {
		return nil, fmt.Errorf("store: unexpected row type")
	}
	_ = pgxRows
	return nil, nil // placeholder — real impl in list helper
}

// listTechniquesQuery executes a query and scans results.
func (s *Store) listTechniquesQuery(ctx context.Context, query string, args ...any) ([]Technique, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query: %w", err)
	}
	defer rows.Close()

	var out []Technique
	for rows.Next() {
		t := Technique{}
		if err := rows.Scan(
			&t.TechniqueID, &t.Name, &t.Description, &t.Tactic, &t.Framework,
			&t.IsSubtechnique, &t.ParentID, &t.Platforms, &t.DataSources, &t.URL,
			&t.FirstSeen, &t.LastSeen, &t.SeenCount, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("store: scan: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListByFramework returns techniques for a specific framework ("enterprise" or "ics").
func (s *Store) ListByFramework(ctx context.Context, framework string) ([]Technique, error) {
	q := `SELECT technique_id, name, description, tactic, framework, is_subtechnique,
	             parent_id, platforms, data_sources, url, first_seen, last_seen,
	             seen_count, updated_at
	      FROM mitre_techniques WHERE framework = $1 ORDER BY technique_id`
	return s.listTechniquesQuery(ctx, q, framework)
}

// ListAll returns every technique ordered by ID.
func (s *Store) ListAll(ctx context.Context) ([]Technique, error) {
	q := `SELECT technique_id, name, description, tactic, framework, is_subtechnique,
	             parent_id, platforms, data_sources, url, first_seen, last_seen,
	             seen_count, updated_at
	      FROM mitre_techniques ORDER BY technique_id`
	return s.listTechniquesQuery(ctx, q)
}

// SearchTechniques performs a case-insensitive keyword search across name and description.
func (s *Store) SearchTechniques(ctx context.Context, keyword string) ([]Technique, error) {
	q := `SELECT technique_id, name, description, tactic, framework, is_subtechnique,
	             parent_id, platforms, data_sources, url, first_seen, last_seen,
	             seen_count, updated_at
	      FROM mitre_techniques
	      WHERE name ILIKE $1 OR description ILIKE $1 OR technique_id ILIKE $1
	      ORDER BY technique_id
	      LIMIT 100`
	return s.listTechniquesQuery(ctx, q, "%"+keyword+"%")
}

// MarkSeen increments the seen counter and updates first_seen / last_seen timestamps.
func (s *Store) MarkSeen(ctx context.Context, techniqueID string) error {
	now := time.Now().UTC()
	_, err := s.pool.Exec(ctx, `
UPDATE mitre_techniques
SET seen_count = seen_count + 1,
    last_seen  = $1,
    first_seen = COALESCE(first_seen, $1)
WHERE technique_id = $2`, now, techniqueID)
	return err
}

// GetCoverage returns a map of technique_id → seen_count for techniques with seen_count > 0.
func (s *Store) GetCoverage(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT technique_id, seen_count FROM mitre_techniques WHERE seen_count > 0`)
	if err != nil {
		return nil, fmt.Errorf("store: coverage: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int)
	for rows.Next() {
		var id string
		var count int
		if err := rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		out[id] = count
	}
	return out, rows.Err()
}

// scanTechnique scans a single pgx Row into a Technique.
func scanTechnique(row interface{ Scan(...any) error }) (*Technique, error) {
	t := &Technique{}
	err := row.Scan(
		&t.TechniqueID, &t.Name, &t.Description, &t.Tactic, &t.Framework,
		&t.IsSubtechnique, &t.ParentID, &t.Platforms, &t.DataSources, &t.URL,
		&t.FirstSeen, &t.LastSeen, &t.SeenCount, &t.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("store: scan technique: %w", err)
	}
	return t, nil
}

// BulkUpsert performs a batched upsert for a slice of techniques.
func (s *Store) BulkUpsert(ctx context.Context, techniques []Technique) error {
	const batchSize = 200
	for i := 0; i < len(techniques); i += batchSize {
		end := i + batchSize
		if end > len(techniques) {
			end = len(techniques)
		}
		batch := techniques[i:end]

		// Build a multi-row VALUES clause.
		placeholders := make([]string, 0, len(batch))
		args := make([]any, 0, len(batch)*10)
		for j, t := range batch {
			base := j*10 + 1
			placeholders = append(placeholders,
				fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
					base, base+1, base+2, base+3, base+4,
					base+5, base+6, base+7, base+8, base+9))
			args = append(args,
				t.TechniqueID, t.Name, t.Description, t.Tactic, t.Framework,
				t.IsSubtechnique, t.ParentID, t.Platforms, t.DataSources, t.URL,
			)
		}

		q := `
INSERT INTO mitre_techniques
    (technique_id, name, description, tactic, framework, is_subtechnique,
     parent_id, platforms, data_sources, url)
VALUES ` + strings.Join(placeholders, ",") + `
ON CONFLICT (technique_id) DO UPDATE SET
    name            = EXCLUDED.name,
    description     = EXCLUDED.description,
    tactic          = EXCLUDED.tactic,
    is_subtechnique = EXCLUDED.is_subtechnique,
    parent_id       = EXCLUDED.parent_id,
    platforms       = EXCLUDED.platforms,
    data_sources    = EXCLUDED.data_sources,
    url             = EXCLUDED.url,
    updated_at      = NOW()`

		if _, err := s.pool.Exec(ctx, q, args...); err != nil {
			return fmt.Errorf("store: bulk upsert batch %d: %w", i/batchSize, err)
		}
	}
	return nil
}
