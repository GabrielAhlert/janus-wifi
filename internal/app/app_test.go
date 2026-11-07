package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"janus/internal/config"
)

func TestEnsureMasterKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{
		DatabaseURL:   "sqlite://" + filepath.Join(dir, "janus.db"),
		MasterKeyFile: filepath.Join(dir, "secrets", "master_key"),
	}
	os.Mkdir(filepath.Dir(cfg.MasterKeyFile), 0o700)
	db, err := openDB(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Instalação nova: gera e grava a chave com permissão restrita.
	key, err := ensureMasterKey(ctx, cfg, db, log)
	if err != nil || len(key) != 32 {
		t.Fatalf("primeiro boot: %d bytes, %v", len(key), err)
	}
	info, err := os.Stat(cfg.MasterKeyFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("arquivo da chave: %v, %v", info, err)
	}
	reloaded, _ := os.ReadFile(cfg.MasterKeyFile)
	if got, _ := config.DecodeMasterKey(string(reloaded)); string(got) != string(key) {
		t.Fatal("a chave gravada difere da devolvida")
	}

	// Com dados cifrados no banco, chave ausente é erro (nunca gera outra).
	if _, _, err := db.CreateKey(ctx, "connection", "2026-11", []byte("x")); err != nil {
		t.Fatal(err)
	}
	os.Remove(cfg.MasterKeyFile)
	_, err = ensureMasterKey(ctx, cfg, db, log)
	if err == nil || !strings.Contains(err.Error(), "restaure") {
		t.Fatalf("erro = %v, esperado recusa por dados existentes", err)
	}
	if _, err := os.Stat(cfg.MasterKeyFile); err == nil {
		t.Fatal("não deveria ter criado uma chave nova")
	}

	// Chave já carregada pela config é usada como está.
	cfg.MasterKey = key
	if got, err := ensureMasterKey(ctx, cfg, db, log); err != nil || string(got) != string(key) {
		t.Fatalf("chave da config: %v", err)
	}
}

func TestOpenDBRejectsUnknownScheme(t *testing.T) {
	_, err := openDB(context.Background(), config.Config{DatabaseURL: "mysql://root:segredo@db/janus"})
	if err == nil || strings.Contains(err.Error(), "segredo") {
		t.Fatalf("erro = %v; esperado recusa sem expor a senha", err)
	}
}
