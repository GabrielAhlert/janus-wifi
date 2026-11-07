package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"janus/internal/core"
)

func (db *DB) CreateSession(ctx context.Context, s *core.SessionRecord, index []core.IndexEntry) error {
	plain, err := json.Marshal(s.Plain)
	if err != nil {
		return err
	}
	return db.inTx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			INSERT INTO sessions (site_id, terms_id, created_at, expires_at, ssid, data_plain, payload)
			VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			s.SiteID, s.TermsID, micros(s.CreatedAt), micros(s.ExpiresAt), s.SSID, string(plain), s.Payload).Scan(&s.ID)
		if err != nil {
			return err
		}
		for _, e := range index {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO session_index (kind, bidx, session_id) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`,
				e.Kind, e.Value, s.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

func (db *DB) SessionCountsSince(ctx context.Context, since time.Time) (map[int64]int64, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT site_id, count(*) FROM sessions WHERE created_at >= ? GROUP BY site_id`, micros(since))
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

func (db *DB) DeleteConnectionDataBefore(ctx context.Context, cutoff time.Time) (sessions, events int64, err error) {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM sessions WHERE created_at < ?`, micros(cutoff))
	if err != nil {
		return 0, 0, err
	}
	sessions, _ = res.RowsAffected()
	res, err = db.sql.ExecContext(ctx, `DELETE FROM log_events WHERE received_at < ?`, micros(cutoff))
	if err != nil {
		return sessions, 0, err
	}
	events, _ = res.RowsAffected()
	return sessions, events, nil
}
