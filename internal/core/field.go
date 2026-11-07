package core

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strings"
)

// FieldType define como um campo do formulário é exibido e validado.
type FieldType string

const (
	FieldText     FieldType = "text"
	FieldEmail    FieldType = "email"
	FieldPhone    FieldType = "phone"
	FieldCPF      FieldType = "cpf"
	FieldCheckbox FieldType = "checkbox"
)

var FieldTypes = []FieldType{FieldText, FieldEmail, FieldPhone, FieldCPF, FieldCheckbox}

func (t FieldType) Label() string {
	switch t {
	case FieldEmail:
		return "E-mail"
	case FieldPhone:
		return "Telefone"
	case FieldCPF:
		return "CPF"
	case FieldCheckbox:
		return "Caixa de seleção"
	default:
		return "Texto"
	}
}

// InputType é o atributo type do <input> no portal.
func (t FieldType) InputType() string {
	switch t {
	case FieldEmail:
		return "email"
	case FieldPhone:
		return "tel"
	case FieldCheckbox:
		return "checkbox"
	default:
		return "text"
	}
}

// Protection define como o valor de um campo é guardado.
type Protection string

const (
	// ProtectEncrypted cifra o valor; só é possível lê-lo decifrando a sessão.
	ProtectEncrypted Protection = "encrypted"
	// ProtectIndexed cifra o valor e grava um índice cego para busca exata.
	ProtectIndexed Protection = "indexed"
	// ProtectPlain guarda em texto puro (opt-ins, dados não pessoais).
	ProtectPlain Protection = "plain"
)

var Protections = []Protection{ProtectEncrypted, ProtectIndexed, ProtectPlain}

func (p Protection) Label() string {
	switch p {
	case ProtectIndexed:
		return "Cifrado + pesquisável"
	case ProtectPlain:
		return "Texto puro"
	default:
		return "Cifrado"
	}
}

// Field é um campo do formulário do portal, configurado no painel.
type Field struct {
	ID          int64
	SiteID      int64
	Key         string // identificador interno, imutável depois de criado
	Label       string
	Placeholder string
	Purpose     string // finalidade declarada (LGPD, art. 6º)
	Type        FieldType
	Protection  Protection
	Required    bool
	Enabled     bool
	Position    int
}

var fieldKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func (f Field) Validate() error {
	switch {
	case !fieldKeyRe.MatchString(f.Key):
		return errors.New("a chave deve começar com letra e ter só letras minúsculas, números ou _")
	case strings.TrimSpace(f.Label) == "":
		return errors.New("o rótulo é obrigatório")
	case !slices.Contains(FieldTypes, f.Type):
		return fmt.Errorf("tipo de campo desconhecido: %q", f.Type)
	case !slices.Contains(Protections, f.Protection):
		return fmt.Errorf("forma de armazenamento desconhecida: %q", f.Protection)
	}
	return nil
}

const maxValueLen = 200

// Normalize valida o valor enviado pelo visitante e o devolve em forma
// canônica. É essa forma que alimenta o índice cego, então
// "123.456.789-09" e "12345678909" geram o mesmo índice.
func (f Field) Normalize(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if f.Type == FieldCheckbox {
		if v != "" {
			return "sim", nil
		}
		if f.Required {
			return "", fmt.Errorf("%s: marque esta opção para continuar", f.Label)
		}
		return "", nil
	}
	if v == "" {
		if f.Required {
			return "", fmt.Errorf("%s é obrigatório", f.Label)
		}
		return "", nil
	}
	if len(v) > maxValueLen {
		return "", fmt.Errorf("%s: valor muito longo", f.Label)
	}

	switch f.Type {
	case FieldEmail:
		addr, err := mail.ParseAddress(v)
		if err != nil || addr.Address != v {
			return "", fmt.Errorf("%s: e-mail inválido", f.Label)
		}
		return strings.ToLower(v), nil
	case FieldPhone:
		d := onlyDigits(v)
		if len(d) < 10 || len(d) > 13 {
			return "", fmt.Errorf("%s: telefone inválido (informe DDD + número)", f.Label)
		}
		return d, nil
	case FieldCPF:
		d, err := NormalizeCPF(v)
		if err != nil {
			return "", fmt.Errorf("%s: CPF inválido", f.Label)
		}
		return d, nil
	}
	return v, nil
}

// DefaultFields são os campos criados junto com um site novo.
func DefaultFields() []Field {
	return []Field{
		{Key: "nome", Label: "Nome completo", Type: FieldText, Protection: ProtectEncrypted, Required: true, Enabled: true, Position: 10,
			Purpose: "Identificação do usuário da rede (Marco Civil da Internet)"},
		{Key: "email", Label: "E-mail", Type: FieldEmail, Protection: ProtectIndexed, Required: true, Enabled: true, Position: 20,
			Purpose: "Identificação e contato"},
		{Key: "telefone", Label: "Celular", Placeholder: "(11) 91234-5678", Type: FieldPhone, Protection: ProtectEncrypted, Enabled: true, Position: 30,
			Purpose: "Contato"},
		{Key: "cpf", Label: "CPF", Placeholder: "000.000.000-00", Type: FieldCPF, Protection: ProtectIndexed, Required: true, Position: 40,
			Purpose: "Identificação inequívoca do usuário"},
	}
}
