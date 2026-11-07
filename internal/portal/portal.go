// Package portal é o portal cativo visto pelos visitantes.
//
// Rotas:
//
//	GET  /guest/s/{site}/         página de cadastro (destino do redirecionamento do controlador)
//	POST /guest/s/{site}/connect  grava o cadastro e libera o acesso
//	GET  /assets/{id}             logos e imagens enviadas pelo painel
package portal

import (
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"janus/internal/core"
	"janus/internal/hotspot"
	"janus/internal/plugin/wifi"
	"janus/internal/sites"
	"janus/internal/store/postgres"
	"janus/web"
)

const (
	ticketTTL = 30 * time.Minute
	maxForm   = 64 << 10
)

// ticket guarda, assinado, o que o controlador informou no
// redirecionamento. Assim o POST do formulário não consegue trocar o MAC.
type ticket struct {
	SiteID int64       `json:"s"`
	Client wifi.Client `json:"c"`
}

type Handler struct {
	db      *postgres.DB
	sites   *sites.Service
	hotspot *hotspot.Service
	signer  Signer
	tmpl    *web.Set
	log     *slog.Logger
}

func New(db *postgres.DB, s *sites.Service, h *hotspot.Service, signer Signer, tmpl *web.Set, log *slog.Logger) *Handler {
	return &Handler{db: db, sites: s, hotspot: h, signer: signer, tmpl: tmpl, log: log}
}

// view é o dado de todas as páginas do portal.
type view struct {
	Theme       core.Theme
	CustomCSS   template.CSS
	Fields      []core.Field
	Terms       core.Terms
	Values      map[string]string
	Errors      []string
	Ticket      string
	Action      string
	Preview     bool
	RedirectURL string
	Message     string
}

func newView(t core.Theme) view {
	// Validado no painel: sem "<", não sai da tag <style>.
	return view{Theme: t, CustomCSS: template.CSS(t.CustomCSS), Values: map[string]string{}}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /guest/s/{site}/", h.landing)
	mux.HandleFunc("POST /guest/s/{site}/connect", h.connect)
	mux.Handle("GET /assets/{id}", AssetHandler(h.db))
	mux.Handle("GET /static/", web.Static())
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		h.renderError(w, http.StatusNotFound, core.DefaultTheme(), "Conecte-se à rede Wi-Fi de visitantes para acessar esta página.")
	})
	return securityHeaders(mux)
}

func (h *Handler) landing(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	site, err := h.sites.BySlug(ctx, r.PathValue("site"))
	if err != nil {
		h.siteError(w, err)
		return
	}
	ctrl, err := h.sites.Controller(site)
	if err != nil {
		h.log.Error("controlador indisponível", "site", site.Slug, "err", err)
		h.renderError(w, http.StatusServiceUnavailable, site.Theme, "O portal ainda não está configurado. Procure a recepção.")
		return
	}
	client, err := ctrl.ParseRedirect(r.URL.Query())
	if err != nil {
		h.renderError(w, http.StatusBadRequest, site.Theme, "Não identificamos seu dispositivo. Desconecte e conecte-se novamente à rede Wi-Fi.")
		return
	}
	tok, err := h.signer.Sign(ticket{SiteID: site.ID, Client: client}, ticketTTL)
	if err != nil {
		h.fail(w, site.Theme, err)
		return
	}
	v, err := h.formView(r, site)
	if err != nil {
		h.fail(w, site.Theme, err)
		return
	}
	v.Ticket, v.Action = tok, connectPath(site)
	h.render(w, http.StatusOK, "form", v)
}

func (h *Handler) connect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		h.renderError(w, http.StatusBadRequest, core.DefaultTheme(), "Formulário inválido.")
		return
	}
	var t ticket
	if err := h.signer.Verify(r.PostForm.Get("ticket"), &t); err != nil {
		h.renderError(w, http.StatusBadRequest, core.DefaultTheme(), "Sua sessão expirou. Desconecte e conecte-se novamente à rede Wi-Fi.")
		return
	}
	site, err := h.sites.Get(ctx, t.SiteID)
	if err == nil && site.Slug != r.PathValue("site") {
		err = postgres.ErrNotFound
	}
	if err != nil {
		h.siteError(w, err)
		return
	}

	values := map[string]string{}
	for k, vs := range r.PostForm {
		if key, ok := strings.CutPrefix(k, "f_"); ok && len(vs) > 0 {
			values[key] = vs[0]
		}
	}
	_, err = h.hotspot.Connect(ctx, hotspot.Request{
		Site:          site,
		Client:        t.Client,
		ClientIP:      clientIP(r),
		UserAgent:     r.UserAgent(),
		Values:        values,
		AcceptedTerms: r.PostForm.Get("accept") != "",
	})

	var verr *hotspot.ValidationError
	switch {
	case errors.As(err, &verr):
		v, ferr := h.formView(r, site)
		if ferr != nil {
			h.fail(w, site.Theme, ferr)
			return
		}
		v.Values, v.Errors = values, verr.Messages
		v.Ticket, v.Action = r.PostForm.Get("ticket"), connectPath(site)
		h.render(w, http.StatusUnprocessableEntity, "form", v)
	case err != nil:
		h.log.Error("falha ao liberar visitante", "site", site.Slug, "err", err)
		h.renderError(w, http.StatusBadGateway, site.Theme, "Não foi possível liberar seu acesso agora. Tente novamente em instantes.")
	default:
		v := newView(site.Theme)
		v.RedirectURL = redirectTarget(site.Theme, t.Client.RedirectURL)
		h.render(w, http.StatusOK, "success", v)
	}
}

// Preview mostra o portal do site como o visitante veria, sem enviar nada.
// Usado pelo painel admin; page pode ser "form" ou "success".
func (h *Handler) Preview(w http.ResponseWriter, r *http.Request, site core.Site, page string) error {
	if page == "success" {
		v := newView(site.Theme)
		v.Preview = true
		h.render(w, http.StatusOK, "success", v)
		return nil
	}
	v, err := h.formView(r, site)
	if err != nil {
		return err
	}
	v.Preview = true
	h.render(w, http.StatusOK, "form", v)
	return nil
}

func (h *Handler) formView(r *http.Request, site core.Site) (view, error) {
	v := newView(site.Theme)
	fields, err := h.hotspot.EnabledFields(r.Context(), site.ID)
	if err != nil {
		return v, err
	}
	terms, err := h.db.CurrentTerms(r.Context(), site.ID)
	if err != nil {
		return v, err
	}
	v.Fields, v.Terms = fields, terms
	return v, nil
}

func (h *Handler) render(w http.ResponseWriter, status int, page string, v view) {
	if err := h.tmpl.Render(w, status, page, v); err != nil {
		h.log.Error("render do portal", "pagina", page, "err", err)
	}
}

func (h *Handler) renderError(w http.ResponseWriter, status int, t core.Theme, msg string) {
	v := newView(t)
	v.Message = msg
	h.render(w, status, "error", v)
}

func (h *Handler) siteError(w http.ResponseWriter, err error) {
	if errors.Is(err, postgres.ErrNotFound) {
		h.renderError(w, http.StatusNotFound, core.DefaultTheme(), "Rede não encontrada.")
		return
	}
	h.fail(w, core.DefaultTheme(), err)
}

func (h *Handler) fail(w http.ResponseWriter, t core.Theme, err error) {
	h.log.Error("erro no portal", "err", err)
	h.renderError(w, http.StatusInternalServerError, t, "Ocorreu um erro. Tente novamente em instantes.")
}

func connectPath(site core.Site) string {
	return "/guest/s/" + url.PathEscape(site.Slug) + "/connect"
}

// redirectTarget escolhe para onde mandar o visitante depois de liberado.
func redirectTarget(t core.Theme, original string) string {
	if t.RedirectURL != "" {
		return t.RedirectURL
	}
	if u, err := url.Parse(original); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		return u.String()
	}
	return ""
}

// clientIP é o IP do visitante na rede de convidados. Se o portal ficar atrás
// de um proxy reverso, este é o ponto para ler X-Forwarded-For de um proxy confiável.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// AssetHandler serve imagens enviadas pelo painel. O id nunca muda de
// conteúdo, então o cache pode ser longo.
func AssetHandler(db *postgres.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		mime, data, err := db.Asset(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Write(data)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
