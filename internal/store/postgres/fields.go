package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"janus/internal/core"
)

const fieldColumns = `id, site_id, key, label, type, placeholder, purpose, protection, required, enabled, position`

func scanField(row pgx.Row) (core.Field, error) {
	var f core.Field
	var typ, prot string
	err := row.Scan(&f.ID, &f.SiteID, &f.Key, &f.Label, &typ, &f.Placeholder, &f.Purpose, &prot, &f.Required, &f.Enabled, &f.Position)
	f.Type, f.Protection = core.FieldType(typ), core.Protection(prot)
	return f, mapErr(err)
}

// Fields devolve todos os campos do site (ativos e inativos) na ordem de exibição.
func (db *DB) Fields(ctx context.Context, siteID int64) ([]core.Field, error) {
	rows, err := db.pool.Query(ctx, `SELECT `+fieldColumns+` FROM fields WHERE site_id = $1 ORDER BY position, id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.Field
	for rows.Next() {
		f, err := scanField(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (db *DB) Field(ctx context.Context, siteID, id int64) (core.Field, error) {
	return scanField(db.pool.QueryRow(ctx, `SELECT `+fieldColumns+` FROM fields WHERE site_id = $1 AND id = $2`, siteID, id))
}

func (db *DB) CreateField(ctx context.Context, f *core.Field) error {
	return insertField(ctx, db.pool, f)
}

func insertField(ctx context.Context, q querier, f *core.Field) error {
	err := q.QueryRow(ctx, `
		INSERT INTO fields (site_id, key, label, type, placeholder, purpose, protection, required, enabled, position)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		f.SiteID, f.Key, f.Label, string(f.Type), f.Placeholder, f.Purpose, string(f.Protection), f.Required, f.Enabled, f.Position).Scan(&f.ID)
	return mapErr(err)
}

// UpdateField altera tudo menos a chave, que identifica o dado já coletado.
func (db *DB) UpdateField(ctx context.Context, f core.Field) error {
	return expectRow(db.pool.Exec(ctx, `
		UPDATE fields SET label = $3, type = $4, placeholder = $5, purpose = $6, protection = $7,
			required = $8, enabled = $9, position = $10
		WHERE site_id = $1 AND id = $2`,
		f.SiteID, f.ID, f.Label, string(f.Type), f.Placeholder, f.Purpose, string(f.Protection), f.Required, f.Enabled, f.Position))
}

func (db *DB) DeleteField(ctx context.Context, siteID, id int64) error {
	return expectRow(db.pool.Exec(ctx, `DELETE FROM fields WHERE site_id = $1 AND id = $2`, siteID, id))
}
