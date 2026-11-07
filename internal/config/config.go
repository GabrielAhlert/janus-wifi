// Package config lê a configuração do processo a partir de variáveis de ambiente.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL string
	MasterKey   []byte

	PortalAddr string // portal cativo, acessado pelos visitantes
	AdminAddr  string // painel admin; mantenha numa rede de gestão
	SyslogAddr string // UDP e TCP

	// SecureCookies marca o cookie do painel como Secure (exige HTTPS).
	SecureCookies bool
}

func Load() (Config, error) {
	c := Config{
		DatabaseURL:   os.Getenv("JANUS_DATABASE_URL"),
		PortalAddr:    env("JANUS_PORTAL_ADDR", ":8080"),
		AdminAddr:     env("JANUS_ADMIN_ADDR", "127.0.0.1:8081"),
		SyslogAddr:    env("JANUS_SYSLOG_ADDR", ":5514"),
		SecureCookies: os.Getenv("JANUS_INSECURE_COOKIES") != "1",
	}
	if c.DatabaseURL == "" {
		return c, errors.New("defina JANUS_DATABASE_URL")
	}
	key, err := masterKey()
	if err != nil {
		return c, err
	}
	c.MasterKey = key
	return c, nil
}

// masterKey lê a chave de JANUS_MASTER_KEY_FILE (preferível) ou JANUS_MASTER_KEY.
func masterKey() ([]byte, error) {
	raw := os.Getenv("JANUS_MASTER_KEY")
	if path := os.Getenv("JANUS_MASTER_KEY_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("ler chave mestra: %w", err)
		}
		raw = string(b)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("defina JANUS_MASTER_KEY_FILE ou JANUS_MASTER_KEY (gere com: janus keygen)")
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("a chave mestra deve ter 32 bytes em base64 (gere com: janus keygen)")
	}
	return key, nil
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
