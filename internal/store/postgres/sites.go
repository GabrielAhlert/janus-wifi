package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"janus/internal/core"
)

const siteColumns = `id, slug, name, controller, controller_config, session_minutes, theme, updated_at`

func scanSite(row pgx.Row) (core.Site, error) {
	var s core.Site
	var theme []byte
	if err := row.Scan(&s.ID, &s.Slug, &s.Name, &s.Controller, &s.ControllerSealed, &s.SessionMinutes, &theme, &s.UpdatedAt); err != nil {
		return s, mapErr(err)
	}
	// Começa do padrão para que campos novos do tema tenham valor em sites antigos.
	s.Theme = core.DefaultTheme()
	if err := json.Unmarshal(theme, &s.Theme); err != nil {
		return s, fmt.Errorf("tema do site %d: %w", s.ID, err)
	}
	return s, nil
}

func (db *DB) Sites(ctx context.Context) ([]core.Site, error) {
	rows, err := db.pool.Query(ctx, `SELECT `+siteColumns+` FROM sites ORDER BY name`)
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
	return scanSite(db.pool.QueryRow(ctx, `SELECT `+siteColumns+` FROM sites WHERE id = $1`, id))
}

func (db *DB) SiteBySlug(ctx context.Context, slug string) (core.Site, error) {
	return scanSite(db.pool.QueryRow(ctx, `SELECT `+siteColumns+` FROM sites WHERE slug = $1`, slug))
}

// CreateSite cria o site já com os campos e a primeira versão dos termos.
func (db *DB) CreateSite(ctx context.Context, s *core.Site, fields []core.Field, terms core.Terms) error {
	theme, err := json.Marshal(s.Theme)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO sites (slug, name, controller, controller_config, session_minutes, theme)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, updated_at`,
			s.Slug, s.Name, s.Controller, s.ControllerSealed, s.SessionMinutes, string(theme)).Scan(&s.ID, &s.UpdatedAt)
		if err != nil {
			return mapErr(err)
		}
		for i := range fields {
			fields[i].SiteID = s.ID
			if err := insertField(ctx, tx, &fields[i]); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO terms (site_id, version, title, body) VALUES ($1, 1, $2, $3)`,
			s.ID, terms.Title, terms.Body)
		return err
	})
}

func (db *DB) UpdateSite(ctx context.Context, s *core.Site) error {
	theme, err := json.Marshal(s.Theme)
	if err != nil {
		return err
	}
	err = db.pool.QueryRow(ctx, `
		UPDATE sites SET slug = $2, name = $3, controller = $4, controller_config = $5,
			session_minutes = $6, theme = $7, updated_at = now()
		WHERE id = $1 RETURNING updated_at`,
		s.ID, s.Slug, s.Name, s.Controller, s.ControllerSealed, s.SessionMinutes, string(theme)).Scan(&s.UpdatedAt)
	return mapErr(err)
}
