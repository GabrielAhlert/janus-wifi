// Package admin é o painel administrativo. Ele roda num listener separado
// do portal, para poder ficar restrito à rede de gestão.
//
// Cada página fica no seu arquivo (sites.go, appearance.go, fields.go,
// terms.go, logsources.go, settings.go) e usa o template de mesmo nome.
package admin

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"janus/internal/core"
	"janus/internal/ingest"
	"janus/internal/portal"
	"janus/internal/sites"
	"janus/internal/store"
	"janus/web"
)

type Deps struct {
	DB        store.Store
	Sites     *sites.Service
	Portal    *portal.Handler
	Templates *web.Set
	Stats     func() ingest.Stats
	// ReloadLogSources avisa o pipeline de logs que as fontes mudaram.
	ReloadLogSources func()
	Log              *slog.Logger
	SecureCookies    bool
	// AllowedNets restringe o painel a estas redes; vazio libera todas.
	AllowedNets []netip.Prefix
}

type Handler struct{ Deps }

func New(d Deps) *Handler { return &Handler{d} }

// appHandler é um handler autenticado; erros viram página de erro.
type appHandler func(w http.ResponseWriter, r *http.Request, a core.Admin) error

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", h.loginForm)
	mux.HandleFunc("POST /login", h.login)
	mux.Handle("GET /static/", web.Static())
	mux.Handle("GET /assets/{id}", portal.AssetHandler(h.DB))

	auth := func(pattern string, fn appHandler) { mux.Handle(pattern, h.auth(fn)) }
	auth("POST /logout", h.logout)
	auth("GET /{$}", h.dashboard)

	auth("GET /sites/new", h.newSite)
	auth("POST /sites", h.createSite)
	auth("GET /sites/{id}", h.editSite)
	auth("POST /sites/{id}", h.updateSite)
	auth("GET /sites/{id}/appearance", h.appearance)
	auth("POST /sites/{id}/appearance", h.saveAppearance)
	auth("GET /sites/{id}/fields", h.fields)
	auth("POST /sites/{id}/fields", h.createField)
	auth("POST /sites/{id}/fields/{fid}", h.updateField)
	auth("POST /sites/{id}/fields/{fid}/delete", h.deleteField)
	auth("GET /sites/{id}/terms", h.terms)
	auth("POST /sites/{id}/terms", h.publishTerms)
	auth("GET /sites/{id}/preview", h.preview)

	auth("GET /log-sources", h.logSources)
	auth("POST /log-sources", h.createLogSource)
	auth("POST /log-sources/{id}/delete", h.deleteLogSource)

	auth("GET /settings", h.settings)
	auth("POST /settings", h.saveSettings)

	// CrossOriginProtection bloqueia POSTs vindos de outras origens (CSRF).
	return securityHeaders(allowNets(h.AllowedNets, http.NewCrossOriginProtection().Handler(mux)))
}

// page é o dado comum a todas as páginas do painel.
type page struct {
	Title string
	Admin *core.Admin
	Site  *core.Site // preenchido nas páginas de um site (mostra as abas)
	Tab   string
	Saved bool
	Error string
	Data  any
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	p.Saved = r.URL.Query().Has("saved")
	if err := h.Templates.Render(w, status, name, p); err != nil {
		h.Log.Error("render do painel", "pagina", name, "err", err)
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, a core.Admin, err error) {
	status, msg := http.StatusInternalServerError, "Erro interno. Veja os logs do servidor."
	if errors.Is(err, store.ErrNotFound) {
		status, msg = http.StatusNotFound, "Página não encontrada."
	} else {
		h.Log.Error("erro no painel", "path", r.URL.Path, "err", err)
	}
	h.render(w, r, status, "error", page{Title: "Erro", Admin: &a, Error: msg})
}

func (h *Handler) audit(r *http.Request, a core.Admin, action string, detail any) {
	if err := h.DB.Audit(r.Context(), a.ID, action, detail); err != nil {
		h.Log.Error("falha ao gravar auditoria", "acao", action, "err", err)
	}
}

func (h *Handler) siteFromPath(r *http.Request) (core.Site, error) {
	id, err := pathID(r, "id")
	if err != nil {
		return core.Site{}, store.ErrNotFound
	}
	return h.Sites.Get(r.Context(), id)
}

func pathID(r *http.Request, name string) (int64, error) {
	return strconv.ParseInt(r.PathValue(name), 10, 64)
}

func redirectSaved(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, path+"?saved=1", http.StatusSeeOther)
}

func formText(r *http.Request, name string) string { return strings.TrimSpace(r.FormValue(name)) }

func formBool(r *http.Request, name string) bool { return r.FormValue(name) != "" }

func formInt(r *http.Request, name string, def int) int {
	n, err := strconv.Atoi(formText(r, name))
	if err != nil {
		return def
	}
	return n
}

// allowNets recusa conexões de fora das redes permitidas (JANUS_ADMIN_ALLOW).
// É uma segunda barreira: o firewall deve bloquear o painel para visitantes.
func allowNets(nets []netip.Prefix, next http.Handler) http.Handler {
	if len(nets) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			ip := ap.Addr().Unmap()
			for _, n := range nets {
				if n.Contains(ip) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		http.Error(w, "O painel não está acessível a partir desta rede.", http.StatusForbidden)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
