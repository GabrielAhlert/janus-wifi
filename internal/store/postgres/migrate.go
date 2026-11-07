package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
)

//go:embed migrations/*.sql
var migrations embed.FS

// migrationLock é o id do advisory lock que impede duas instâncias de
// migrarem ao mesmo tempo.
const migrationLock = 7420001

// Migrate aplica, em ordem, os arquivos de migrations/ ainda não aplicados.
func (db *DB) Migrate(ctx context.Context) error {
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLock)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}

	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		version := e.Name()
		var applied bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrations.ReadFile("migrations/" + version)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("migração %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}
