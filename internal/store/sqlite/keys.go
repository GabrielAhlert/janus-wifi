package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"janus/internal/vault"
)

func (db *DB) FindKey(ctx context.Context, scope, period string) (uint32, []byte, error) {
	var id int64
	var wrapped []byte
	err := db.sql.QueryRowContext(ctx,
		`SELECT id, wrapped FROM data_keys WHERE scope = ? AND period = ?`, scope, period).Scan(&id, &wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, vault.ErrKeyNotFound
	}
	if err != nil {
		return 0, nil, err
	}
	if wrapped == nil {
		return 0, nil, vault.ErrKeyDestroyed
	}
	return uint32(id), wrapped, nil
}

func (db *DB) CreateKey(ctx context.Context, scope, period string, wrapped []byte) (uint32, []byte, error) {
	if _, err := db.sql.ExecContext(ctx,
		`INSERT INTO data_keys (scope, period, wrapped, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (scope, period) DO NOTHING`,
		scope, period, wrapped, now()); err != nil {
		return 0, nil, err
	}
	return db.FindKey(ctx, scope, period)
}

func (db *DB) GetKey(ctx context.Context, id uint32) (string, string, []byte, error) {
	var scope, period string
	var wrapped []byte
	err := db.sql.QueryRowContext(ctx,
		`SELECT scope, period, wrapped FROM data_keys WHERE id = ?`, int64(id)).Scan(&scope, &period, &wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil, vault.ErrKeyNotFound
	}
	if err != nil {
		return "", "", nil, err
	}
	if wrapped == nil {
		return "", "", nil, vault.ErrKeyDestroyed
	}
	return scope, period, wrapped, nil
}

func (db *DB) HasDataKeys(ctx context.Context) (bool, error) {
	var ok bool
	err := db.sql.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM data_keys)`).Scan(&ok)
	return ok, err
}

func (db *DB) DestroyKeysBefore(ctx context.Context, scope, period string) ([]uint32, error) {
	rows, err := db.sql.QueryContext(ctx, `
		UPDATE data_keys SET wrapped = NULL, destroyed_at = ?
		WHERE scope = ? AND period < ? AND wrapped IS NOT NULL
		RETURNING id`, now(), scope, period)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uint32
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, uint32(id))
	}
	return ids, rows.Err()
}
