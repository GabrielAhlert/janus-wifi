package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"janus/internal/core"
)

const termsColumns = `id, site_id, version, title, body, created_at`

func scanTerms(row pgx.Row) (core.Terms, error) {
	var t core.Terms
	err := row.Scan(&t.ID, &t.SiteID, &t.Version, &t.Title, &t.Body, &t.CreatedAt)
	return t, mapErr(err)
}

// CurrentTerms devolve a versão vigente (a mais recente) dos termos do site.
func (db *DB) CurrentTerms(ctx context.Context, siteID int64) (core.Terms, error) {
	return scanTerms(db.pool.QueryRow(ctx,
		`SELECT `+termsColumns+` FROM terms WHERE site_id = $1 ORDER BY version DESC LIMIT 1`, siteID))
}

func (db *DB) TermsHistory(ctx context.Context, siteID int64) ([]core.Terms, error) {
	rows, err := db.pool.Query(ctx, `SELECT `+termsColumns+` FROM terms WHERE site_id = $1 ORDER BY version DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.Terms
	for rows.Next() {
		t, err := scanTerms(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// PublishTerms grava uma nova versão; versões anteriores nunca são alteradas.
func (db *DB) PublishTerms(ctx context.Context, siteID int64, title, body string, adminID int64) (core.Terms, error) {
	t := core.Terms{SiteID: siteID, Title: title, Body: body}
	err := db.pool.QueryRow(ctx, `
		INSERT INTO terms (site_id, version, title, body, created_by)
		SELECT $1, COALESCE(MAX(version), 0) + 1, $2, $3, $4 FROM terms WHERE site_id = $1
		RETURNING id, version, created_at`, siteID, title, body, adminID).Scan(&t.ID, &t.Version, &t.CreatedAt)
	return t, mapErr(err)
}
