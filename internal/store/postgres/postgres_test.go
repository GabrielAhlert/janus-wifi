package postgres

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"janus/internal/store"
	"janus/internal/store/storetest"
)

// Os testes rodam só com JANUS_TEST_POSTGRES_URL definida. Cada subteste
// ganha um schema próprio, apagado no fim.
func open(t *testing.T) store.Store {
	t.Helper()
	base := os.Getenv("JANUS_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("defina JANUS_TEST_POSTGRES_URL para testar o driver Postgres")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("test_%d", time.Now().UnixNano())
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(context.Background())
	})

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	db, err := Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestContract(t *testing.T) { storetest.Run(t, open) }

func TestDescribeHidesPassword(t *testing.T) {
	if os.Getenv("JANUS_TEST_POSTGRES_URL") == "" {
		t.Skip("defina JANUS_TEST_POSTGRES_URL para testar o driver Postgres")
	}
	db, err := Open(context.Background(), os.Getenv("JANUS_TEST_POSTGRES_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	u, _ := url.Parse(os.Getenv("JANUS_TEST_POSTGRES_URL"))
	if pw, ok := u.User.Password(); ok && strings.Contains(db.Describe(), pw) {
		t.Fatalf("Describe expõe a senha: %q", db.Describe())
	}
}
