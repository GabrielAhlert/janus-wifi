// Package plugin define o que é comum a todos os tipos de plugin: a
// descrição dos campos de configuração que o painel admin renderiza.
//
// Cada tipo de plugin tem seu subpacote com interface e registro próprios:
//   - plugin/wifi: controladores que liberam o acesso (UniFi, ...)
//   - plugin/logs: parsers de syslog de firewall/gateway (UCG, ...)
//
// Os plugins embutidos são habilitados em plugin/all.
package plugin

import (
	"fmt"
	"strconv"
	"strings"
)

type FieldType string

const (
	Text     FieldType = "text"
	Password FieldType = "password"
	Bool     FieldType = "bool"
	Number   FieldType = "number"
)

// ConfigField descreve um campo de configuração de plugin; o painel gera o
// formulário a partir desta lista.
type ConfigField struct {
	Key      string
	Label    string
	Help     string
	Type     FieldType
	Required bool
	Secret   bool // nunca é reexibido no painel
	Default  string
}

// Apply valida a configuração enviada pelo painel. Campos secretos deixados
// em branco mantêm o valor anterior, para a senha não precisar ser redigitada.
func Apply(fields []ConfigField, previous, submitted map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(fields))
	for _, f := range fields {
		v := strings.TrimSpace(submitted[f.Key])
		switch {
		case f.Type == Bool:
			v = strconv.FormatBool(v == "true" || v == "on" || v == "1")
		case v == "" && f.Secret:
			v = previous[f.Key]
		case v == "":
			v = f.Default
		}
		if f.Type == Number && v != "" {
			if _, err := strconv.Atoi(v); err != nil {
				return nil, fmt.Errorf("%s: informe um número", f.Label)
			}
		}
		if f.Required && v == "" {
			return nil, fmt.Errorf("%s é obrigatório", f.Label)
		}
		if v != "" {
			out[f.Key] = v
		}
	}
	return out, nil
}
