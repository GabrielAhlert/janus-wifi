package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"janus/internal/store"
	"janus/internal/store/storetest"
)

func open(t *testing.T) store.Store {
	t.Helper()
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "sub", "janus.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestContract(t *testing.T) { storetest.Run(t, open) }

func TestDatabaseFileIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "janus.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("permissão do banco = %o, esperado 600", perm)
	}
}
