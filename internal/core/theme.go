package core

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Theme é tudo o que o painel permite personalizar no visual do portal.
type Theme struct {
	PrimaryColor    string `json:"primary_color"`
	BackgroundColor string `json:"background_color"`
	CardColor       string `json:"card_color"`
	TextColor       string `json:"text_color"`

	Title        string `json:"title"`
	Welcome      string `json:"welcome"`
	ButtonText   string `json:"button_text"`
	TermsLabel   string `json:"terms_label"`
	SuccessTitle string `json:"success_title"`
	SuccessText  string `json:"success_text"`
	Footer       string `json:"footer"`

	// RedirectURL, se definido, substitui a página que o visitante tentou abrir.
	RedirectURL string `json:"redirect_url"`

	LogoAsset       int64 `json:"logo_asset,omitempty"`
	BackgroundAsset int64 `json:"background_asset,omitempty"`

	CustomCSS string `json:"custom_css"`
}

func DefaultTheme() Theme {
	return Theme{
		PrimaryColor:    "#2563eb",
		BackgroundColor: "#0f172a",
		CardColor:       "#ffffff",
		TextColor:       "#0f172a",
		Title:           "Wi-Fi Visitantes",
		Welcome:         "Preencha seus dados para acessar a internet.",
		ButtonText:      "Conectar",
		TermsLabel:      "Li e aceito os termos de uso",
		SuccessTitle:    "Você está conectado!",
		SuccessText:     "Aproveite a navegação.",
	}
}

var colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

const (
	maxThemeText = 500
	maxCustomCSS = 20000
)

func (t Theme) Validate() error {
	colors := []struct{ name, value string }{
		{"cor principal", t.PrimaryColor},
		{"cor de fundo", t.BackgroundColor},
		{"cor do cartão", t.CardColor},
		{"cor do texto", t.TextColor},
	}
	for _, c := range colors {
		if !colorRe.MatchString(c.value) {
			return fmt.Errorf("%s inválida: use o formato #RRGGBB", c.name)
		}
	}
	for _, s := range []string{t.Title, t.Welcome, t.ButtonText, t.TermsLabel, t.SuccessTitle, t.SuccessText, t.Footer} {
		if len(s) > maxThemeText {
			return fmt.Errorf("texto muito longo (máximo %d caracteres)", maxThemeText)
		}
	}
	if strings.TrimSpace(t.ButtonText) == "" {
		return errors.New("o texto do botão é obrigatório")
	}
	if t.RedirectURL != "" {
		u, err := url.Parse(t.RedirectURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("o endereço de redirecionamento deve começar com http:// ou https://")
		}
	}
	// O CSS vai dentro de um <style>; bloquear "<" impede fechar a tag.
	if strings.Contains(t.CustomCSS, "<") {
		return errors.New("o CSS personalizado não pode conter o caractere <")
	}
	if len(t.CustomCSS) > maxCustomCSS {
		return errors.New("o CSS personalizado é grande demais")
	}
	return nil
}
