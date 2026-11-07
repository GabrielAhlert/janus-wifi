package admin

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"janus/internal/core"
)

const (
	maxUpload = 8 << 20
	maxImage  = 3 << 20
)

// Formatos aceitos, detectados pelo conteúdo e não pela extensão. SVG fica
// de fora porque pode carregar scripts.
var imageTypes = []string{"image/png", "image/jpeg", "image/gif", "image/webp"}

func (h *Handler) appearance(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s, err := h.siteFromPath(r)
	if err != nil {
		return err
	}
	h.renderAppearance(w, r, a, s, s.Theme, http.StatusOK, "")
	return nil
}

func (h *Handler) renderAppearance(w http.ResponseWriter, r *http.Request, a core.Admin, s core.Site, t core.Theme, status int, errMsg string) {
	h.render(w, r, status, "appearance", page{Title: "Aparência · " + s.Name, Admin: &a, Site: &s, Tab: "appearance", Error: errMsg, Data: t})
}

func (h *Handler) saveAppearance(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s, err := h.siteFromPath(r)
	if err != nil {
		return err
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		h.renderAppearance(w, r, a, s, s.Theme, http.StatusRequestEntityTooLarge, "Arquivos grandes demais (máximo 3 MB por imagem).")
		return nil
	}

	t := s.Theme
	t.PrimaryColor = formText(r, "primary_color")
	t.BackgroundColor = formText(r, "background_color")
	t.CardColor = formText(r, "card_color")
	t.TextColor = formText(r, "text_color")
	t.Title = formText(r, "title")
	t.Welcome = formText(r, "welcome")
	t.ButtonText = formText(r, "button_text")
	t.TermsLabel = formText(r, "terms_label")
	t.SuccessTitle = formText(r, "success_title")
	t.SuccessText = formText(r, "success_text")
	t.Footer = formText(r, "footer")
	t.RedirectURL = formText(r, "redirect_url")
	t.CustomCSS = r.FormValue("custom_css")

	images := []struct {
		field, remove string
		dst           *int64
	}{
		{"logo", "remove_logo", &t.LogoAsset},
		{"background", "remove_background", &t.BackgroundAsset},
	}
	for _, img := range images {
		if formBool(r, img.remove) {
			*img.dst = 0
		}
		id, err := h.upload(r, img.field)
		if msg, ok := userError(err, ""); ok {
			h.renderAppearance(w, r, a, s, t, http.StatusUnprocessableEntity, msg)
			return nil
		} else if err != nil {
			return err
		}
		if id != 0 {
			*img.dst = id
		}
	}

	if err := t.Validate(); err != nil {
		h.renderAppearance(w, r, a, s, t, http.StatusUnprocessableEntity, err.Error())
		return nil
	}
	s.Theme = t
	if err := h.Sites.Save(r.Context(), &s); err != nil {
		return err
	}
	h.audit(r, a, "site.appearance", map[string]any{"site": s.ID})
	redirectSaved(w, r, fmt.Sprintf("/sites/%d/appearance", s.ID))
	return nil
}

// upload grava a imagem enviada no campo name e devolve o id do asset (0 se
// nenhum arquivo foi enviado).
func (h *Handler) upload(r *http.Request, name string) (int64, error) {
	f, _, err := r.FormFile(name)
	if errors.Is(err, http.ErrMissingFile) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxImage+1))
	if err != nil {
		return 0, err
	}
	if len(data) > maxImage {
		return 0, formError{"Imagem grande demais (máximo 3 MB)."}
	}
	mime := http.DetectContentType(data)
	if !slices.Contains(imageTypes, mime) {
		return 0, formError{"Formato de imagem não suportado. Use PNG, JPEG, GIF ou WebP."}
	}
	return h.DB.CreateAsset(r.Context(), mime, data)
}
