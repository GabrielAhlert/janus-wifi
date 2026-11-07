package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"janus/internal/core"
)

const siteColumns = `id, slug, name, controller, controller_config, session_minutes, theme, updated_at`

func scanSite(row scanner) (core.Site, error) {
	var s core.Site
	var theme string
	var updated int64
	if err := row.Scan(&s.ID, &s.Slug, &s.Name, &s.Controller, &s.ControllerSealed, &s.SessionMinutes, &theme, &updated); err != nil {
		return s, mapErr(err)
	}
	s.UpdatedAt = fromMicros(updated)
	// Começa do padrão para que campos novos do tema tenham valor em sites antigos.
	s.Theme = core.DefaultTheme()
	if err := json.Unmarshal([]byte(theme), &s.Theme); err != nil {
		return s, fmt.Errorf("tema do site %d: %w", s.ID, err)
	}
	return s, nil
}

func (db *DB) Sites(ctx context.Context) ([]core.Site, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+siteColumns+` FROM sites ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.Site
	for rows.Next() {
		s, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) Site(ctx context.Context, id int64) (core.Site, error) {
	return scanSite(db.sql.QueryRowContext(ctx, `SELECT `+siteColumns+` FROM sites WHERE id = ?`, id))
}

func (db *DB) SiteBySlug(ctx context.Context, slug string) (core.Site, error) {
	return scanSite(db.sql.QueryRowContext(ctx, `SELECT `+siteColumns+` FROM sites WHERE slug = ?`, slug))
}

func (db *DB) CreateSite(ctx context.Context, s *core.Site, fields []core.Field, terms core.Terms) error {
	theme, err := json.Marshal(s.Theme)
	if err != nil {
		return err
	}
	ts := time.Now().UTC().Truncate(time.Microsecond)
	return db.inTx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			INSERT INTO sites (slug, name, controller, controller_config, session_minutes, theme, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			s.Slug, s.Name, s.Controller, s.ControllerSealed, s.SessionMinutes, string(theme), micros(ts), micros(ts)).Scan(&s.ID)
		if err != nil {
			return mapErr(err)
		}
		s.UpdatedAt = ts
		for i := range fields {
			fields[i].SiteID = s.ID
			if err := insertField(ctx, tx, &fields[i]); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO terms (site_id, version, title, body, created_at) VALUES (?, 1, ?, ?, ?)`,
			s.ID, terms.Title, terms.Body, micros(ts))
		return err
	})
}

func (db *DB) UpdateSite(ctx context.Context, s *core.Site) error {
	theme, err := json.Marshal(s.Theme)
	if err != nil {
		return err
	}
	ts := time.Now().UTC().Truncate(time.Microsecond)
	err = expectRow(db.sql.ExecContext(ctx, `
		UPDATE sites SET slug = ?, name = ?, controller = ?, controller_config = ?,
			session_minutes = ?, theme = ?, updated_at = ?
		WHERE id = ?`,
		s.Slug, s.Name, s.Controller, s.ControllerSealed, s.SessionMinutes, string(theme), micros(ts), s.ID))
	if err == nil {
		s.UpdatedAt = ts
	}
	return err
}
