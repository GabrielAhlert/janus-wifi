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

func TestDescribeHidesCredentials(t *testing.T) {
	cfg, err := pgx.ParseConfig("postgres://usuario-x:senha-secreta-123@db.lan:5433/janus")
	if err != nil {
		t.Fatal(err)
	}
	got := describe(cfg)
	if want := "PostgreSQL em db.lan:5433/janus"; got != want {
		t.Fatalf("describe = %q, quer %q", got, want)
	}
	for _, secret := range []string{"senha-secreta-123", "usuario-x"} {
		if strings.Contains(got, secret) {
			t.Fatalf("describe expõe %q: %q", secret, got)
		}
	}
}
