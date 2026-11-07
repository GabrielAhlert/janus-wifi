package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"janus/internal/core"
)

// CreateSession grava a sessão e seus índices cegos numa única transação.
func (db *DB) CreateSession(ctx context.Context, s *core.SessionRecord, index []core.IndexEntry) error {
	plain, err := json.Marshal(s.Plain)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO sessions (site_id, terms_id, created_at, expires_at, ssid, data_plain, payload)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
			s.SiteID, s.TermsID, s.CreatedAt, s.ExpiresAt, s.SSID, string(plain), s.Payload).Scan(&s.ID)
		if err != nil {
			return err
		}
		for _, e := range index {
			if _, err := tx.Exec(ctx,
				`INSERT INTO session_index (kind, bidx, session_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
				e.Kind, e.Value, s.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// SessionCountsSince conta sessões por site a partir de since.
func (db *DB) SessionCountsSince(ctx context.Context, since time.Time) (map[int64]int64, error) {
	rows, err := db.pool.Query(ctx, `SELECT site_id, count(*) FROM sessions WHERE created_at >= $1 GROUP BY site_id`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var site, n int64
		if err := rows.Scan(&site, &n); err != nil {
			return nil, err
		}
		out[site] = n
	}
	return out, rows.Err()
}

// DeleteConnectionDataBefore remove sessões e eventos de log anteriores a cutoff.
func (db *DB) DeleteConnectionDataBefore(ctx context.Context, cutoff time.Time) (sessions, events int64, err error) {
	tag, err := db.pool.Exec(ctx, `DELETE FROM sessions WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, 0, err
	}
	sessions = tag.RowsAffected()
	tag, err = db.pool.Exec(ctx, `DELETE FROM log_events WHERE received_at < $1`, cutoff)
	if err != nil {
		return sessions, 0, err
	}
	return sessions, tag.RowsAffected(), nil
}
