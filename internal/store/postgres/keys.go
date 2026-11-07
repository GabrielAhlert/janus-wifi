package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"janus/internal/vault"
)

// Os métodos abaixo implementam vault.KeyStore.

func (db *DB) FindKey(ctx context.Context, scope, period string) (uint32, []byte, error) {
	var id int32
	var wrapped []byte
	err := db.pool.QueryRow(ctx,
		`SELECT id, wrapped FROM data_keys WHERE scope = $1 AND period = $2`, scope, period).Scan(&id, &wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
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
	// Em corrida, outra instância pode ter criado a chave antes; nesse caso
	// vale a que já está no banco.
	if _, err := db.pool.Exec(ctx,
		`INSERT INTO data_keys (scope, period, wrapped) VALUES ($1, $2, $3) ON CONFLICT (scope, period) DO NOTHING`,
		scope, period, wrapped); err != nil {
		return 0, nil, err
	}
	return db.FindKey(ctx, scope, period)
}

func (db *DB) GetKey(ctx context.Context, id uint32) (string, string, []byte, error) {
	var scope, period string
	var wrapped []byte
	err := db.pool.QueryRow(ctx,
		`SELECT scope, period, wrapped FROM data_keys WHERE id = $1`, int32(id)).Scan(&scope, &period, &wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
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
	err := db.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM data_keys)`).Scan(&ok)
	return ok, err
}

func (db *DB) DestroyKeysBefore(ctx context.Context, scope, period string) ([]uint32, error) {
	rows, err := db.pool.Query(ctx, `
		UPDATE data_keys SET wrapped = NULL, destroyed_at = now()
		WHERE scope = $1 AND period < $2 AND wrapped IS NOT NULL
		RETURNING id`, scope, period)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int32])
	if err != nil {
		return nil, err
	}
	out := make([]uint32, len(ids))
	for i, id := range ids {
		out[i] = uint32(id)
	}
	return out, nil
}
