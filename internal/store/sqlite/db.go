// Package sqlite é o driver de store.Store para SQLite, o padrão para
// instalações de um container só (ex.: Unraid). Usa modernc.org/sqlite, em
// Go puro, para manter o binário estático.
//
// O SQLite aceita um escritor por vez. Com WAL e busy_timeout, isso basta
// para o portal e o pipeline de logs (que já grava em lote); para volumes
// muito altos de syslog, use o driver postgres.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"janus/internal/store"
)

var _ store.Store = (*DB)(nil)

//go:embed migrations/*.sql
var migrations embed.FS

type DB struct {
	sql  *sql.DB
	path string
}

// pragmas valem para cada conexão do pool. _txlock=immediate faz as
// transações pegarem o lock de escrita no BEGIN, evitando deadlocks.
const pragmas = "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate"

func Open(ctx context.Context, path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("informe o caminho do arquivo SQLite (ex.: sqlite:///data/janus.db)")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("criar diretório do banco: %w", err)
	}
	// Cria o arquivo com permissão restrita antes que o SQLite o crie com a padrão.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("abrir banco SQLite: %w", err)
	}
	f.Close()

	db, err := sql.Open("sqlite", "file:"+path+pragmas)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("abrir banco SQLite: %w", err)
	}
	return &DB{sql: db, path: path}, nil
}

func (db *DB) Close() { db.sql.Close() }

func (db *DB) Describe() string { return "SQLite em " + db.path }

// Migrate aplica, em ordem, os arquivos de migrations/ ainda não aplicados.
func (db *DB) Migrate(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		version := e.Name()
		var applied int
		if err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, version).Scan(&applied); err != nil {
			return err
		}
		if applied > 0 {
			continue
		}
		script, err := migrations.ReadFile("migrations/" + version)
		if err != nil {
			return err
		}
		err = db.inTx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, string(script)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, version, now())
			return err
		})
		if err != nil {
			return fmt.Errorf("migração %s: %w", version, err)
		}
	}
	return nil
}

// querier é satisfeito tanto por *sql.DB quanto por *sql.Tx.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// scanner é satisfeito por *sql.Row e *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func (db *DB) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func mapErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	var se *sqlite.Error
	if errors.As(err, &se) && (se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY) {
		return store.ErrConflict
	}
	return err
}

func expectRow(res sql.Result, err error) error {
	if err != nil {
		return mapErr(err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// As datas ficam em microssegundos Unix, a mesma precisão do Postgres.

func micros(t time.Time) int64 { return t.UnixMicro() }

func fromMicros(n int64) time.Time { return time.UnixMicro(n).UTC() }

func now() int64 { return time.Now().UnixMicro() }
