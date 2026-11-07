package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"janus/internal/core"
)

func (db *DB) CreateAdmin(ctx context.Context, email, passwordHash string) error {
	_, err := db.pool.Exec(ctx, `INSERT INTO admins (email, password_hash) VALUES ($1, $2)`, email, passwordHash)
	return mapErr(err)
}

// AdminCredentials devolve o administrador e o hash da senha para o login.
func (db *DB) AdminCredentials(ctx context.Context, email string) (core.Admin, string, error) {
	var a core.Admin
	var hash string
	err := db.pool.QueryRow(ctx, `SELECT id, email, created_at, password_hash FROM admins WHERE email = $1`, email).
		Scan(&a.ID, &a.Email, &a.CreatedAt, &hash)
	return a, hash, mapErr(err)
}

func (db *DB) CreateAdminSession(ctx context.Context, tokenHash []byte, adminID int64, expires time.Time) error {
	_, err := db.pool.Exec(ctx, `INSERT INTO admin_sessions (token_hash, admin_id, expires_at) VALUES ($1, $2, $3)`,
		tokenHash, adminID, expires)
	return err
}

func (db *DB) AdminBySession(ctx context.Context, tokenHash []byte) (core.Admin, error) {
	var a core.Admin
	err := db.pool.QueryRow(ctx, `
		SELECT a.id, a.email, a.created_at FROM admin_sessions s JOIN admins a ON a.id = s.admin_id
		WHERE s.token_hash = $1 AND s.expires_at > now()`, tokenHash).Scan(&a.ID, &a.Email, &a.CreatedAt)
	return a, mapErr(err)
}

func (db *DB) DeleteAdminSession(ctx context.Context, tokenHash []byte) error {
	_, err := db.pool.Exec(ctx, `DELETE FROM admin_sessions WHERE token_hash = $1 OR expires_at < now()`, tokenHash)
	return err
}

// Audit registra uma ação administrativa.
func (db *DB) Audit(ctx context.Context, adminID int64, action string, detail any) error {
	d, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = db.pool.Exec(ctx, `INSERT INTO audit_log (admin_id, action, detail) VALUES ($1, $2, $3)`, adminID, action, string(d))
	return err
}

func (db *DB) CreateAsset(ctx context.Context, mime string, data []byte) (int64, error) {
	var id int64
	err := db.pool.QueryRow(ctx, `INSERT INTO assets (mime, data) VALUES ($1, $2) RETURNING id`, mime, data).Scan(&id)
	return id, err
}

func (db *DB) Asset(ctx context.Context, id int64) (mime string, data []byte, err error) {
	err = db.pool.QueryRow(ctx, `SELECT mime, data FROM assets WHERE id = $1`, id).Scan(&mime, &data)
	return mime, data, mapErr(err)
}

// DefaultRetentionMonths segue o prazo mínimo do Marco Civil (art. 13).
const DefaultRetentionMonths = 12

func (db *DB) RetentionMonths(ctx context.Context) (int, error) {
	var n int
	err := db.pool.QueryRow(ctx, `SELECT (value)::int FROM settings WHERE key = 'retention_months'`).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultRetentionMonths, nil
	}
	return n, err
}

func (db *DB) SetRetentionMonths(ctx context.Context, months int) error {
	_, err := db.pool.Exec(ctx, `
		INSERT INTO settings (key, value) VALUES ('retention_months', to_jsonb($1::int))
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, months)
	return err
}
