// Package config lê a configuração do processo a partir de variáveis de ambiente.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"strings"
)

// DefaultDatabaseURL é um SQLite no volume de dados do container.
const DefaultDatabaseURL = "sqlite:///data/janus.db"

type Config struct {
	// DatabaseURL escolhe o driver: sqlite:///caminho ou postgres://...
	DatabaseURL string

	// MasterKey é a chave mestra já decodificada. Fica nil quando
	// MasterKeyFile aponta para um arquivo que ainda não existe; nesse caso
	// o serve pode gerá-la (ver app.ensureMasterKey).
	MasterKey     []byte
	MasterKeyFile string

	PortalAddr string // portal cativo, acessado pelos visitantes
	AdminAddr  string // painel admin; mantenha numa rede de gestão
	SyslogAddr string // UDP e TCP

	// AdminAllow restringe o painel a estas redes; vazio libera todas.
	AdminAllow []netip.Prefix

	// SecureCookies marca o cookie do painel como Secure (exige HTTPS).
	SecureCookies bool
}

func Load() (Config, error) {
	c := Config{
		DatabaseURL:   env("JANUS_DATABASE_URL", DefaultDatabaseURL),
		MasterKeyFile: os.Getenv("JANUS_MASTER_KEY_FILE"),
		PortalAddr:    env("JANUS_PORTAL_ADDR", ":8080"),
		AdminAddr:     env("JANUS_ADMIN_ADDR", "127.0.0.1:8081"),
		SyslogAddr:    env("JANUS_SYSLOG_ADDR", ":5514"),
		SecureCookies: os.Getenv("JANUS_INSECURE_COOKIES") != "1",
	}
	nets, err := ParseNets(os.Getenv("JANUS_ADMIN_ALLOW"))
	if err != nil {
		return c, err
	}
	c.AdminAllow = nets

	switch {
	case os.Getenv("JANUS_MASTER_KEY") != "":
		c.MasterKey, err = DecodeMasterKey(os.Getenv("JANUS_MASTER_KEY"))
	case c.MasterKeyFile != "":
		b, rerr := os.ReadFile(c.MasterKeyFile)
		if errors.Is(rerr, fs.ErrNotExist) {
			return c, nil // pode ser a primeira inicialização
		}
		if rerr != nil {
			return c, fmt.Errorf("ler chave mestra: %w", rerr)
		}
		c.MasterKey, err = DecodeMasterKey(string(b))
	}
	return c, err
}

// DecodeMasterKey valida e decodifica a chave mestra (32 bytes em base64).
func DecodeMasterKey(raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(key) != 32 {
		return nil, errors.New("a chave mestra deve ter 32 bytes em base64 (gere com: janus keygen)")
	}
	return key, nil
}

// ParseNets lê redes separadas por vírgula. Um IP sem máscara vale só para ele.
func ParseNets(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("JANUS_ADMIN_ALLOW: %q não é um IP nem uma rede (ex.: 192.168.1.0/24)", part)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
