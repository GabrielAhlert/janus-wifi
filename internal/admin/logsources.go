package admin

import (
	"net/http"
	"net/netip"

	"janus/internal/core"
	"janus/internal/plugin/logs"
)

type logSourcesData struct {
	Sources []core.LogSource
	Parsers []logs.Driver
}

func (h *Handler) logSources(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	return h.renderLogSources(w, r, a, http.StatusOK, "")
}

func (h *Handler) renderLogSources(w http.ResponseWriter, r *http.Request, a core.Admin, status int, errMsg string) error {
	sources, err := h.DB.LogSources(r.Context())
	if err != nil {
		return err
	}
	h.render(w, r, status, "log_sources", page{Title: "Fontes de log", Admin: &a, Error: errMsg,
		Data: logSourcesData{Sources: sources, Parsers: logs.Drivers()}})
	return nil
}

func (h *Handler) createLogSource(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s := core.LogSource{Name: formText(r, "name"), Parser: formText(r, "parser"), Enabled: true}
	ip, err := netip.ParseAddr(formText(r, "sender_ip"))
	switch {
	case s.Name == "":
		err = formError{"Informe um nome."}
	case err != nil:
		err = formError{"IP de origem inválido."}
	default:
		s.SenderIP = ip.Unmap()
		if _, ok := logs.Lookup(s.Parser); !ok {
			err = formError{"Parser desconhecido."}
		} else {
			err = h.DB.CreateLogSource(r.Context(), &s)
		}
	}
	if msg, ok := userError(err, "Já existe uma fonte com esse IP."); ok {
		return h.renderLogSources(w, r, a, http.StatusUnprocessableEntity, msg)
	} else if err != nil {
		return err
	}
	h.ReloadLogSources()
	h.audit(r, a, "log_source.create", map[string]any{"id": s.ID, "ip": s.SenderIP.String(), "parser": s.Parser})
	redirectSaved(w, r, "/log-sources")
	return nil
}

func (h *Handler) deleteLogSource(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	id, err := pathID(r, "id")
	if err != nil {
		return err
	}
	if err := h.DB.DeleteLogSource(r.Context(), id); err != nil {
		return err
	}
	h.ReloadLogSources()
	h.audit(r, a, "log_source.delete", map[string]any{"id": id})
	redirectSaved(w, r, "/log-sources")
	return nil
}
