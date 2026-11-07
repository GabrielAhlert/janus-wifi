package sqlite

import (
	"context"

	"janus/internal/core"
)

const fieldColumns = `id, site_id, key, label, type, placeholder, purpose, protection, required, enabled, position`

func scanField(row scanner) (core.Field, error) {
	var f core.Field
	var typ, prot string
	err := row.Scan(&f.ID, &f.SiteID, &f.Key, &f.Label, &typ, &f.Placeholder, &f.Purpose, &prot, &f.Required, &f.Enabled, &f.Position)
	f.Type, f.Protection = core.FieldType(typ), core.Protection(prot)
	return f, mapErr(err)
}

func (db *DB) Fields(ctx context.Context, siteID int64) ([]core.Field, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+fieldColumns+` FROM fields WHERE site_id = ? ORDER BY position, id`, siteID)
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
	return scanField(db.sql.QueryRowContext(ctx, `SELECT `+fieldColumns+` FROM fields WHERE site_id = ? AND id = ?`, siteID, id))
}

func (db *DB) CreateField(ctx context.Context, f *core.Field) error {
	return insertField(ctx, db.sql, f)
}

func insertField(ctx context.Context, q querier, f *core.Field) error {
	err := q.QueryRowContext(ctx, `
		INSERT INTO fields (site_id, key, label, type, placeholder, purpose, protection, required, enabled, position)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		f.SiteID, f.Key, f.Label, string(f.Type), f.Placeholder, f.Purpose, string(f.Protection), f.Required, f.Enabled, f.Position).Scan(&f.ID)
	return mapErr(err)
}

func (db *DB) UpdateField(ctx context.Context, f core.Field) error {
	return expectRow(db.sql.ExecContext(ctx, `
		UPDATE fields SET label = ?, type = ?, placeholder = ?, purpose = ?, protection = ?,
			required = ?, enabled = ?, position = ?
		WHERE site_id = ? AND id = ?`,
		f.Label, string(f.Type), f.Placeholder, f.Purpose, string(f.Protection), f.Required, f.Enabled, f.Position, f.SiteID, f.ID))
}

func (db *DB) DeleteField(ctx context.Context, siteID, id int64) error {
	return expectRow(db.sql.ExecContext(ctx, `DELETE FROM fields WHERE site_id = ? AND id = ?`, siteID, id))
}
