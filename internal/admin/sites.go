package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"janus/internal/core"
	"janus/internal/ingest"
	"janus/internal/plugin"
	"janus/internal/plugin/wifi"
	"janus/internal/store/postgres"
)

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	ctx := r.Context()
	list, err := h.Sites.List(ctx)
	if err != nil {
		return err
	}
	since := time.Now().Add(-24 * time.Hour)
	counts, err := h.DB.SessionCountsSince(ctx, since)
	if err != nil {
		return err
	}
	events, err := h.DB.LogEventCountSince(ctx, since)
	if err != nil {
		return err
	}

	type siteRow struct {
		core.Site
		Sessions int64
	}
	data := struct {
		Sites     []siteRow
		Events24h int64
		Stats     ingest.Stats
	}{Events24h: events, Stats: h.Stats()}
	for _, s := range list {
		data.Sites = append(data.Sites, siteRow{s, counts[s.ID]})
	}
	h.render(w, r, http.StatusOK, "dashboard", page{Title: "Sites", Admin: &a, Data: data})
	return nil
}

// Formulário geral do site (criação e edição).

type siteData struct {
	Site    core.Site
	Drivers []driverView
	IsNew   bool
}

type driverView struct {
	Name     string
	Label    string
	Selected bool
	Fields   []configFieldView
}

type configFieldView struct {
	plugin.ConfigField
	Value     string
	SecretSet bool
}

// driverViews monta o formulário de cada plugin Wi-Fi. Segredos nunca voltam
// ao navegador: o painel só indica que já existe um valor salvo.
func driverViews(site core.Site) []driverView {
	var out []driverView
	for _, d := range wifi.Drivers() {
		dv := driverView{Name: d.Name, Label: d.Label, Selected: d.Name == site.Controller}
		for _, f := range d.Config {
			fv := configFieldView{ConfigField: f, Value: f.Default}
			if v, ok := site.ControllerConfig[f.Key]; ok && dv.Selected {
				fv.Value = v
			}
			if f.Secret {
				fv.SecretSet = dv.Selected && fv.Value != ""
				fv.Value = ""
			}
			dv.Fields = append(dv.Fields, fv)
		}
		out = append(out, dv)
	}
	return out
}

func (h *Handler) renderSite(w http.ResponseWriter, r *http.Request, a core.Admin, s core.Site, isNew bool, status int, errMsg string) {
	p := page{Title: s.Name, Admin: &a, Tab: "general", Error: errMsg, Data: siteData{Site: s, Drivers: driverViews(s), IsNew: isNew}}
	if isNew {
		p.Title = "Novo site"
	} else {
		p.Site = &s
	}
	h.render(w, r, status, "site", p)
}

func (h *Handler) newSite(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	h.renderSite(w, r, a, core.Site{SessionMinutes: 480, Theme: core.DefaultTheme()}, true, http.StatusOK, "")
	return nil
}

func (h *Handler) createSite(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s, err := siteFromForm(r, core.Site{Theme: core.DefaultTheme()})
	if err == nil {
		err = h.Sites.Create(r.Context(), &s)
	}
	if msg, ok := userError(err, "Já existe um site com esse slug."); ok {
		h.renderSite(w, r, a, s, true, http.StatusUnprocessableEntity, msg)
		return nil
	} else if err != nil {
		return err
	}
	h.audit(r, a, "site.create", map[string]any{"site": s.ID, "slug": s.Slug})
	redirectSaved(w, r, fmt.Sprintf("/sites/%d", s.ID))
	return nil
}

func (h *Handler) editSite(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s, err := h.siteFromPath(r)
	if err != nil {
		return err
	}
	h.renderSite(w, r, a, s, false, http.StatusOK, "")
	return nil
}

func (h *Handler) updateSite(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	current, err := h.siteFromPath(r)
	if err != nil {
		return err
	}
	s, err := siteFromForm(r, current)
	if err == nil {
		err = h.Sites.Save(r.Context(), &s)
	}
	if msg, ok := userError(err, "Já existe um site com esse slug."); ok {
		h.renderSite(w, r, a, s, false, http.StatusUnprocessableEntity, msg)
		return nil
	} else if err != nil {
		return err
	}
	h.audit(r, a, "site.update", map[string]any{"site": s.ID, "slug": s.Slug, "controller": s.Controller})
	redirectSaved(w, r, fmt.Sprintf("/sites/%d", s.ID))
	return nil
}

// formError é um erro de preenchimento, mostrado ao administrador.
type formError struct{ msg string }

func (e formError) Error() string { return e.msg }

func invalid(err error) error { return formError{err.Error()} }

// userError traduz o erro para uma mensagem de formulário, se for o caso.
func userError(err error, conflictMsg string) (string, bool) {
	var fe formError
	switch {
	case err == nil:
		return "", false
	case errors.As(err, &fe):
		return fe.msg, true
	case errors.Is(err, postgres.ErrConflict):
		return conflictMsg, true
	}
	return "", false
}

func siteFromForm(r *http.Request, s core.Site) (core.Site, error) {
	s.Name = formText(r, "name")
	s.Slug = strings.ToLower(formText(r, "slug"))
	s.SessionMinutes = formInt(r, "session_minutes", 0)

	driver := formText(r, "controller")
	if driver == "" {
		s.Controller, s.ControllerConfig = "", nil
	} else {
		d, ok := wifi.Lookup(driver)
		if !ok {
			return s, formError{"Plugin Wi-Fi desconhecido."}
		}
		previous := s.ControllerConfig
		if driver != s.Controller {
			previous = nil
		}
		submitted := map[string]string{}
		for _, f := range d.Config {
			submitted[f.Key] = r.FormValue("cfg." + driver + "." + f.Key)
		}
		cfg, err := plugin.Apply(d.Config, previous, submitted)
		if err != nil {
			return s, invalid(err)
		}
		s.Controller, s.ControllerConfig = driver, cfg
	}
	if err := s.Validate(); err != nil {
		return s, invalid(err)
	}
	return s, nil
}

func (h *Handler) preview(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s, err := h.siteFromPath(r)
	if err != nil {
		return err
	}
	return h.Portal.Preview(w, r, s, r.URL.Query().Get("page"))
}
