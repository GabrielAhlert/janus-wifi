package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"janus/internal/core"
	"janus/internal/store"
)

func (db *DB) CreateAdmin(ctx context.Context, email, passwordHash string) error {
	_, err := db.sql.ExecContext(ctx, `INSERT INTO admins (email, password_hash, created_at) VALUES (?, ?, ?)`, email, passwordHash, now())
	return mapErr(err)
}

func (db *DB) AdminCredentials(ctx context.Context, email string) (core.Admin, string, error) {
	var a core.Admin
	var hash string
	var created int64
	err := db.sql.QueryRowContext(ctx, `SELECT id, email, created_at, password_hash FROM admins WHERE email = ?`, email).
		Scan(&a.ID, &a.Email, &created, &hash)
	a.CreatedAt = fromMicros(created)
	return a, hash, mapErr(err)
}

func (db *DB) CreateAdminSession(ctx context.Context, tokenHash []byte, adminID int64, expires time.Time) error {
	_, err := db.sql.ExecContext(ctx, `INSERT INTO admin_sessions (token_hash, admin_id, expires_at) VALUES (?, ?, ?)`,
		tokenHash, adminID, micros(expires))
	return err
}

func (db *DB) AdminBySession(ctx context.Context, tokenHash []byte) (core.Admin, error) {
	var a core.Admin
	var created int64
	err := db.sql.QueryRowContext(ctx, `
		SELECT a.id, a.email, a.created_at FROM admin_sessions s JOIN admins a ON a.id = s.admin_id
		WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, now()).Scan(&a.ID, &a.Email, &created)
	a.CreatedAt = fromMicros(created)
	return a, mapErr(err)
}

func (db *DB) DeleteAdminSession(ctx context.Context, tokenHash []byte) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM admin_sessions WHERE token_hash = ? OR expires_at < ?`, tokenHash, now())
	return err
}

func (db *DB) Audit(ctx context.Context, adminID int64, action string, detail any) error {
	d, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx, `INSERT INTO audit_log (at, admin_id, action, detail) VALUES (?, ?, ?, ?)`, now(), adminID, action, string(d))
	return err
}

func (db *DB) CreateAsset(ctx context.Context, mime string, data []byte) (int64, error) {
	var id int64
	err := db.sql.QueryRowContext(ctx, `INSERT INTO assets (mime, data, created_at) VALUES (?, ?, ?) RETURNING id`, mime, data, now()).Scan(&id)
	return id, err
}

func (db *DB) Asset(ctx context.Context, id int64) (mime string, data []byte, err error) {
	err = db.sql.QueryRowContext(ctx, `SELECT mime, data FROM assets WHERE id = ?`, id).Scan(&mime, &data)
	return mime, data, mapErr(err)
}

func (db *DB) RetentionMonths(ctx context.Context) (int, error) {
	var n int
	err := db.sql.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'retention_months'`).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return store.DefaultRetentionMonths, nil
	}
	return n, err
}

func (db *DB) SetRetentionMonths(ctx context.Context, months int) error {
	_, err := db.sql.ExecContext(ctx, `
		INSERT INTO settings (key, value) VALUES ('retention_months', ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, strconv.Itoa(months))
	return err
}
