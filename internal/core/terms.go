package core

import (
	"regexp"
	"strings"
	"time"
)

// Terms é uma versão publicada dos termos de uso de um site. Versões nunca
// são editadas: cada sessão aponta para a versão que o visitante aceitou.
type Terms struct {
	ID        int64
	SiteID    int64
	Version   int
	Title     string
	Body      string
	CreatedAt time.Time
}

var paragraphSep = regexp.MustCompile(`\n\s*\n`)

// Paragraphs divide o texto em parágrafos separados por linha em branco.
func (t Terms) Paragraphs() []string {
	var out []string
	for _, p := range paragraphSep.Split(strings.ReplaceAll(t.Body, "\r\n", "\n"), -1) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DefaultTerms é o modelo inicial. Ele deve ser revisado pelo jurídico da
// empresa antes de entrar em produção.
func DefaultTerms() Terms {
	return Terms{
		Title: "Termos de uso da rede Wi-Fi",
		Body: `Esta rede é oferecida como cortesia aos visitantes. Ao se conectar, você concorda em utilizá-la de forma lícita, respeitando a legislação vigente e as políticas internas da empresa.

Em cumprimento ao Marco Civil da Internet (Lei nº 12.965/2014), os registros de conexão (data, hora, endereço IP e identificação do dispositivo) são guardados de forma sigilosa pelo prazo legal e só serão fornecidos mediante ordem judicial.

Os dados pessoais informados no cadastro são tratados conforme a Lei Geral de Proteção de Dados (Lei nº 13.709/2018), exclusivamente para identificar o usuário da rede e cumprir obrigações legais. Eles são armazenados cifrados e eliminados ao fim do prazo de retenção.

É proibido usar a rede para atividades ilícitas, envio de spam, ataques a outros sistemas ou violação de direitos de terceiros. O acesso pode ser interrompido a qualquer momento.

Para exercer seus direitos como titular dos dados, entre em contato com o encarregado de dados (DPO) da empresa.`,
	}
}
