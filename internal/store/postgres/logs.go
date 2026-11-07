package postgres

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"janus/internal/core"
)

func (db *DB) LogSources(ctx context.Context) ([]core.LogSource, error) {
	rows, err := db.pool.Query(ctx, `SELECT id, name, sender_ip, parser, enabled, created_at FROM log_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.LogSource
	for rows.Next() {
		var s core.LogSource
		var ip netip.Prefix
		if err := rows.Scan(&s.ID, &s.Name, &ip, &s.Parser, &s.Enabled, &s.CreatedAt); err != nil {
			return nil, err
		}
		s.SenderIP = ip.Addr()
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) CreateLogSource(ctx context.Context, s *core.LogSource) error {
	err := db.pool.QueryRow(ctx,
		`INSERT INTO log_sources (name, sender_ip, parser, enabled) VALUES ($1, $2::inet, $3, $4) RETURNING id, created_at`,
		s.Name, s.SenderIP.String(), s.Parser, s.Enabled).Scan(&s.ID, &s.CreatedAt)
	return mapErr(err)
}

func (db *DB) DeleteLogSource(ctx context.Context, id int64) error {
	return expectRow(db.pool.Exec(ctx, `DELETE FROM log_sources WHERE id = $1`, id))
}

// LastLogHash devolve o hash do último evento gravado, ou nil se não houver.
func (db *DB) LastLogHash(ctx context.Context) ([]byte, error) {
	var h []byte
	err := db.pool.QueryRow(ctx, `SELECT hash FROM log_events ORDER BY id DESC LIMIT 1`).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return h, err
}

// InsertLogEvents grava um lote via COPY. A ordem do lote vira a ordem dos
// ids, o que mantém a cadeia de hashes coerente.
func (db *DB) InsertLogEvents(ctx context.Context, recs []core.LogRecord) error {
	rows := make([][]any, len(recs))
	for i, r := range recs {
		rows[i] = []any{r.ReceivedAt, r.SourceID, r.SrcIPIndex, r.SrcMACIndex, r.Payload, r.PrevHash, r.Hash}
	}
	_, err := db.pool.CopyFrom(ctx, pgx.Identifier{"log_events"},
		[]string{"received_at", "source_id", "src_ip_bidx", "src_mac_bidx", "payload", "prev_hash", "hash"},
		pgx.CopyFromRows(rows))
	return err
}

// ScanLogEvents percorre todos os eventos em ordem de id.
func (db *DB) ScanLogEvents(ctx context.Context, fn func(core.LogRecord) error) error {
	rows, err := db.pool.Query(ctx, `
		SELECT id, received_at, source_id, src_ip_bidx, src_mac_bidx, payload, prev_hash, hash
		FROM log_events ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r core.LogRecord
		if err := rows.Scan(&r.ID, &r.ReceivedAt, &r.SourceID, &r.SrcIPIndex, &r.SrcMACIndex, &r.Payload, &r.PrevHash, &r.Hash); err != nil {
			return err
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (db *DB) LogEventCountSince(ctx context.Context, since time.Time) (int64, error) {
	var n int64
	err := db.pool.QueryRow(ctx, `SELECT count(*) FROM log_events WHERE received_at >= $1`, since).Scan(&n)
	return n, err
}
