package core

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Site é uma rede de visitantes com portal próprio: aparência, campos,
// termos e o controlador Wi-Fi que libera o acesso.
type Site struct {
	ID   int64
	Slug string // usado na URL do portal: /guest/s/<slug>/
	Name string

	// Controller é o nome do plugin Wi-Fi (ex.: "unifi"); vazio = não configurado.
	Controller string
	// ControllerConfig é a configuração do plugin já decifrada (só em memória).
	ControllerConfig map[string]string
	// ControllerSealed é a mesma configuração cifrada, como fica no banco.
	ControllerSealed []byte

	SessionMinutes int
	Theme          Theme
	UpdatedAt      time.Time
}

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func (s Site) Validate() error {
	switch {
	case strings.TrimSpace(s.Name) == "":
		return errors.New("o nome do site é obrigatório")
	case !slugRe.MatchString(s.Slug):
		return errors.New("o slug deve ter letras minúsculas, números, - ou _")
	case s.SessionMinutes < 1 || s.SessionMinutes > 43200:
		return errors.New("a duração da sessão deve ficar entre 1 minuto e 30 dias")
	}
	return nil
}
