package admin

import (
	"fmt"
	"net/http"
	"strings"

	"janus/internal/core"
)

type termsData struct {
	Current core.Terms
	History []core.Terms
	Next    int
}

func (h *Handler) terms(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s, err := h.siteFromPath(r)
	if err != nil {
		return err
	}
	return h.renderTerms(w, r, a, s, nil, http.StatusOK, "")
}

// renderTerms mostra a página; draft, se não for nil, substitui o texto
// vigente no formulário (para não perder o que foi digitado num erro).
func (h *Handler) renderTerms(w http.ResponseWriter, r *http.Request, a core.Admin, s core.Site, draft *core.Terms, status int, errMsg string) error {
	history, err := h.DB.TermsHistory(r.Context(), s.ID)
	if err != nil {
		return err
	}
	data := termsData{History: history, Next: 1}
	if len(history) > 0 {
		data.Current, data.Next = history[0], history[0].Version+1
	}
	if draft != nil {
		data.Current.Title, data.Current.Body = draft.Title, draft.Body
	}
	h.render(w, r, status, "terms", page{Title: "Termos · " + s.Name, Admin: &a, Site: &s, Tab: "terms", Error: errMsg, Data: data})
	return nil
}

func (h *Handler) publishTerms(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s, err := h.siteFromPath(r)
	if err != nil {
		return err
	}
	draft := core.Terms{Title: formText(r, "title"), Body: strings.TrimSpace(strings.ReplaceAll(r.FormValue("body"), "\r\n", "\n"))}
	if draft.Title == "" || draft.Body == "" {
		return h.renderTerms(w, r, a, s, &draft, http.StatusUnprocessableEntity, "Título e texto são obrigatórios.")
	}
	current, err := h.DB.CurrentTerms(r.Context(), s.ID)
	if err != nil {
		return err
	}
	if current.Title == draft.Title && current.Body == draft.Body {
		return h.renderTerms(w, r, a, s, nil, http.StatusOK, "Nada mudou em relação à versão vigente.")
	}
	t, err := h.DB.PublishTerms(r.Context(), s.ID, draft.Title, draft.Body, a.ID)
	if err != nil {
		return err
	}
	h.audit(r, a, "terms.publish", map[string]any{"site": s.ID, "version": t.Version})
	redirectSaved(w, r, fmt.Sprintf("/sites/%d/terms", s.ID))
	return nil
}
