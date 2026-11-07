package sqlite

import (
	"context"

	"janus/internal/core"
)

const termsColumns = `id, site_id, version, title, body, created_at`

func scanTerms(row scanner) (core.Terms, error) {
	var t core.Terms
	var created int64
	err := row.Scan(&t.ID, &t.SiteID, &t.Version, &t.Title, &t.Body, &created)
	t.CreatedAt = fromMicros(created)
	return t, mapErr(err)
}

func (db *DB) CurrentTerms(ctx context.Context, siteID int64) (core.Terms, error) {
	return scanTerms(db.sql.QueryRowContext(ctx,
		`SELECT `+termsColumns+` FROM terms WHERE site_id = ? ORDER BY version DESC LIMIT 1`, siteID))
}

func (db *DB) TermsHistory(ctx context.Context, siteID int64) ([]core.Terms, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+termsColumns+` FROM terms WHERE site_id = ? ORDER BY version DESC`, siteID)
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

func (db *DB) PublishTerms(ctx context.Context, siteID int64, title, body string, adminID int64) (core.Terms, error) {
	t := core.Terms{SiteID: siteID, Title: title, Body: body}
	var created int64
	err := db.sql.QueryRowContext(ctx, `
		INSERT INTO terms (site_id, version, title, body, created_by, created_at)
		SELECT ?1, COALESCE(MAX(version), 0) + 1, ?2, ?3, ?4, ?5 FROM terms WHERE site_id = ?1
		RETURNING id, version, created_at`, siteID, title, body, adminID, now()).Scan(&t.ID, &t.Version, &created)
	t.CreatedAt = fromMicros(created)
	return t, mapErr(err)
}
