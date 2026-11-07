package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestParseNets(t *testing.T) {
	nets, err := ParseNets(" 192.168.1.0/24, 10.0.0.7 ,fd00::/8,192.168.5.9/16")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.1.0/24", "10.0.0.7/32", "fd00::/8", "192.168.0.0/16"}
	if len(nets) != len(want) {
		t.Fatalf("ParseNets = %v", nets)
	}
	for i, w := range want {
		if nets[i] != netip.MustParsePrefix(w) {
			t.Errorf("rede %d = %s, esperado %s", i, nets[i], w)
		}
	}
	if nets, _ := ParseNets(""); len(nets) != 0 {
		t.Fatalf("lista vazia deveria liberar tudo, veio %v", nets)
	}
	if _, err := ParseNets("192.168.1.0/24,rede-da-ti"); err == nil {
		t.Fatal("valor inválido deveria falhar")
	}
}

func TestLoadDefaultsToSQLite(t *testing.T) {
	t.Setenv("JANUS_DATABASE_URL", "")
	t.Setenv("JANUS_MASTER_KEY", "")
	t.Setenv("JANUS_MASTER_KEY_FILE", filepath.Join(t.TempDir(), "master_key"))
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != DefaultDatabaseURL {
		t.Errorf("DatabaseURL = %q", c.DatabaseURL)
	}
	if c.MasterKey != nil {
		t.Error("chave inexistente deveria ficar nil (primeira inicialização)")
	}
}

func TestLoadReadsKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master_key")
	os.WriteFile(path, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), 0o600)
	t.Setenv("JANUS_MASTER_KEY", "")
	t.Setenv("JANUS_MASTER_KEY_FILE", path)
	c, err := Load()
	if err != nil || len(c.MasterKey) != 32 {
		t.Fatalf("Load = %d bytes, %v", len(c.MasterKey), err)
	}

	os.WriteFile(path, []byte("curta"), 0o600)
	if _, err := Load(); err == nil {
		t.Fatal("chave inválida deveria falhar")
	}
}
