package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"time"

	"janus/internal/core"
)

func (db *DB) LogSources(ctx context.Context) ([]core.LogSource, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, name, sender_ip, parser, enabled, created_at FROM log_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.LogSource
	for rows.Next() {
		var s core.LogSource
		var ip string
		var created int64
		if err := rows.Scan(&s.ID, &s.Name, &ip, &s.Parser, &s.Enabled, &created); err != nil {
			return nil, err
		}
		if s.SenderIP, err = netip.ParseAddr(ip); err != nil {
			return nil, err
		}
		s.CreatedAt = fromMicros(created)
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) CreateLogSource(ctx context.Context, s *core.LogSource) error {
	ts := time.Now().UTC().Truncate(time.Microsecond)
	err := db.sql.QueryRowContext(ctx,
		`INSERT INTO log_sources (name, sender_ip, parser, enabled, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id`,
		s.Name, s.SenderIP.Unmap().String(), s.Parser, s.Enabled, micros(ts)).Scan(&s.ID)
	if err == nil {
		s.CreatedAt = ts
	}
	return mapErr(err)
}

func (db *DB) DeleteLogSource(ctx context.Context, id int64) error {
	return expectRow(db.sql.ExecContext(ctx, `DELETE FROM log_sources WHERE id = ?`, id))
}

func (db *DB) LastLogHash(ctx context.Context) ([]byte, error) {
	var h []byte
	err := db.sql.QueryRowContext(ctx, `SELECT hash FROM log_events ORDER BY id DESC LIMIT 1`).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return h, err
}

// InsertLogEvents grava o lote numa transação, na ordem recebida.
func (db *DB) InsertLogEvents(ctx context.Context, recs []core.LogRecord) error {
	return db.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO log_events (received_at, source_id, src_ip_bidx, src_mac_bidx, payload, prev_hash, hash)
			VALUES (?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, r := range recs {
			if _, err := stmt.ExecContext(ctx, micros(r.ReceivedAt), r.SourceID, r.SrcIPIndex, r.SrcMACIndex, r.Payload, r.PrevHash, r.Hash); err != nil {
				return err
			}
		}
		return nil
	})
}

func (db *DB) ScanLogEvents(ctx context.Context, fn func(core.LogRecord) error) error {
	rows, err := db.sql.QueryContext(ctx, `
		SELECT id, received_at, source_id, src_ip_bidx, src_mac_bidx, payload, prev_hash, hash
		FROM log_events ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r core.LogRecord
		var received int64
		if err := rows.Scan(&r.ID, &received, &r.SourceID, &r.SrcIPIndex, &r.SrcMACIndex, &r.Payload, &r.PrevHash, &r.Hash); err != nil {
			return err
		}
		r.ReceivedAt = fromMicros(received)
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (db *DB) LogEventCountSince(ctx context.Context, since time.Time) (int64, error) {
	var n int64
	err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM log_events WHERE received_at >= ?`, micros(since)).Scan(&n)
	return n, err
}
