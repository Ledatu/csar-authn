package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/pgutil"
)

func (s *Store) UpsertUserAttributionTouch(ctx context.Context, touch *store.AttributionTouch) (*store.AttributionTouch, error) {
	if touch == nil {
		return nil, fmt.Errorf("upsert attribution touch: nil touch")
	}

	if touch.ID == uuid.Nil {
		touch.ID = uuid.New()
	}
	now := time.Now().UTC()
	if touch.TouchedAt.IsZero() {
		touch.TouchedAt = now
	}
	if touch.CreatedAt.IsZero() {
		touch.CreatedAt = now
	}
	touch.UpdatedAt = now
	touch.SourceMetadata = store.CloneAttributionMetadata(touch.SourceMetadata)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin attribution upsert tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx,
		`SELECT id, user_id, source_type, source_key, source_metadata, touched_at, expires_at,
		        consumed_at, replaced_by, created_at, updated_at
		 FROM attribution_touches
		 WHERE user_id = $1
		   AND replaced_by IS NULL
		   AND consumed_at IS NULL
		   AND expires_at > now()
		 ORDER BY touched_at DESC
		 FOR UPDATE`,
		touch.UserID,
	)
	if err != nil {
		return nil, fmt.Errorf("query active attribution touches: %w", err)
	}

	var active []*store.AttributionTouch
	for rows.Next() {
		existing, scanErr := scanAttributionTouch(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		active = append(active, existing)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate active attribution touches: %w", err)
	}
	rows.Close()

	for _, existing := range active {
		if !store.SameAttributionTouchSource(existing, touch) {
			continue
		}
		if err := tx.QueryRow(ctx,
			`UPDATE attribution_touches
			 SET touched_at = $2,
			     expires_at = $3,
			     source_metadata = $4,
			     updated_at = $5
			 WHERE id = $1
			 RETURNING id, user_id, source_type, source_key, source_metadata, touched_at, expires_at,
			           consumed_at, replaced_by, created_at, updated_at`,
			existing.ID,
			touch.TouchedAt,
			touch.ExpiresAt,
			stringMetadataJSON(touch.SourceMetadata),
			now,
		).Scan(
			&existing.ID,
			&existing.UserID,
			&existing.SourceType,
			&existing.SourceKey,
			(*jsonbStringMap)(&existing.SourceMetadata),
			&existing.TouchedAt,
			&existing.ExpiresAt,
			&existing.ConsumedAt,
			&existing.ReplacedBy,
			&existing.CreatedAt,
			&existing.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("refresh attribution touch: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit attribution refresh: %w", err)
		}
		existing.SourceMetadata = store.CloneAttributionMetadata(existing.SourceMetadata)
		return existing, nil
	}

	if len(active) > 0 {
		ids := make([]uuid.UUID, 0, len(active))
		for _, existing := range active {
			ids = append(ids, existing.ID)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE attribution_touches
			 SET replaced_by = $2, updated_at = $3
			 WHERE id = ANY($1)`,
			ids, touch.ID, now,
		); err != nil {
			return nil, fmt.Errorf("replace active attribution touches: %w", err)
		}
	}

	created := &store.AttributionTouch{}
	err = tx.QueryRow(ctx,
		`INSERT INTO attribution_touches
		 (id, user_id, source_type, source_key, source_metadata, touched_at, expires_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id, user_id, source_type, source_key, source_metadata, touched_at, expires_at,
		           consumed_at, replaced_by, created_at, updated_at`,
		touch.ID,
		touch.UserID,
		touch.SourceType,
		touch.SourceKey,
		stringMetadataJSON(touch.SourceMetadata),
		touch.TouchedAt,
		touch.ExpiresAt,
		touch.CreatedAt,
		touch.UpdatedAt,
	).Scan(
		&created.ID,
		&created.UserID,
		&created.SourceType,
		&created.SourceKey,
		(*jsonbStringMap)(&created.SourceMetadata),
		&created.TouchedAt,
		&created.ExpiresAt,
		&created.ConsumedAt,
		&created.ReplacedBy,
		&created.CreatedAt,
		&created.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert attribution touch: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit attribution insert: %w", err)
	}

	created.SourceMetadata = store.CloneAttributionMetadata(created.SourceMetadata)
	return created, nil
}

func (s *Store) GetActiveUserAttributionTouch(ctx context.Context, userID uuid.UUID) (*store.AttributionTouch, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, user_id, source_type, source_key, source_metadata, touched_at, expires_at,
		        consumed_at, replaced_by, created_at, updated_at
		 FROM attribution_touches
		 WHERE user_id = $1
		   AND replaced_by IS NULL
		   AND consumed_at IS NULL
		   AND expires_at > now()
		 ORDER BY touched_at DESC
		 LIMIT 1`,
		userID,
	)
	touch, err := scanAttributionTouch(row)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get active attribution touch: %w", err)
	}
	return touch, nil
}

func (s *Store) ConsumeUserAttributionTouch(ctx context.Context, userID, touchID uuid.UUID) (*store.AttributionTouch, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE attribution_touches
		 SET consumed_at = now(), updated_at = now()
		 WHERE id = $1
		   AND user_id = $2
		   AND replaced_by IS NULL
		   AND consumed_at IS NULL
		   AND expires_at > now()
		 RETURNING id, user_id, source_type, source_key, source_metadata, touched_at, expires_at,
		           consumed_at, replaced_by, created_at, updated_at`,
		touchID,
		userID,
	)
	touch, err := scanAttributionTouch(row)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrAttributionUnavailable
	}
	if err != nil {
		return nil, fmt.Errorf("consume attribution touch: %w", err)
	}
	return touch, nil
}

type attributionScanner interface {
	Scan(dest ...any) error
}

func scanAttributionTouch(scanner attributionScanner) (*store.AttributionTouch, error) {
	touch := &store.AttributionTouch{}
	if err := scanner.Scan(
		&touch.ID,
		&touch.UserID,
		&touch.SourceType,
		&touch.SourceKey,
		(*jsonbStringMap)(&touch.SourceMetadata),
		&touch.TouchedAt,
		&touch.ExpiresAt,
		&touch.ConsumedAt,
		&touch.ReplacedBy,
		&touch.CreatedAt,
		&touch.UpdatedAt,
	); err != nil {
		return nil, err
	}
	touch.SourceMetadata = store.CloneAttributionMetadata(touch.SourceMetadata)
	return touch, nil
}

type jsonbStringMap map[string]string

func (m *jsonbStringMap) Scan(src any) error {
	if m == nil {
		return fmt.Errorf("scan jsonb string map: nil destination")
	}
	if src == nil {
		*m = nil
		return nil
	}

	var raw []byte
	switch value := src.(type) {
	case []byte:
		raw = append([]byte(nil), value...)
	case string:
		raw = []byte(value)
	default:
		return fmt.Errorf("scan jsonb string map: unsupported type %T", src)
	}

	if len(raw) == 0 {
		*m = nil
		return nil
	}

	var decoded map[string]string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("scan jsonb string map: %w", err)
	}
	*m = decoded
	return nil
}

func stringMetadataJSON(m map[string]string) []byte {
	if len(m) == 0 {
		return nil
	}
	b, _ := json.Marshal(m)
	return b
}
