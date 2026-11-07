package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"janus/internal/core"
)

const (
	cookieName = "janus_admin"
	sessionTTL = 12 * time.Hour
)

// dummyHash faz o login levar o mesmo tempo quando o e-mail não existe.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("janus-dummy"), bcrypt.DefaultCost)

func (h *Handler) auth(fn appHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := h.currentAdmin(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if err := fn(w, r, a); err != nil {
			h.fail(w, r, a, err)
		}
	})
}

func (h *Handler) currentAdmin(r *http.Request) (core.Admin, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return core.Admin{}, err
	}
	token, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return core.Admin{}, err
	}
	sum := sha256.Sum256(token)
	return h.DB.AdminBySession(r.Context(), sum[:])
}

func (h *Handler) loginForm(w http.ResponseWriter, r *http.Request) {
	if _, err := h.currentAdmin(r); err == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	h.render(w, r, http.StatusOK, "login", page{Title: "Entrar"})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := strings.ToLower(formText(r, "email"))
	a, hash, err := h.DB.AdminCredentials(ctx, email)
	if err != nil {
		hash = string(dummyHash)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.FormValue("password"))) != nil || err != nil {
		h.Log.Warn("login recusado", "email", email, "ip", r.RemoteAddr)
		h.render(w, r, http.StatusUnauthorized, "login", page{Title: "Entrar", Error: "E-mail ou senha inválidos."})
		return
	}

	token := make([]byte, 32)
	rand.Read(token)
	sum := sha256.Sum256(token)
	if err := h.DB.CreateAdminSession(ctx, sum[:], a.ID, time.Now().Add(sessionTTL)); err != nil {
		h.fail(w, r, a, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    base64.RawURLEncoding.EncodeToString(token),
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.SecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
	h.audit(r, a, "login", map[string]string{"ip": r.RemoteAddr})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	if c, err := r.Cookie(cookieName); err == nil {
		if token, err := base64.RawURLEncoding.DecodeString(c.Value); err == nil {
			sum := sha256.Sum256(token)
			h.DB.DeleteAdminSession(r.Context(), sum[:])
		}
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: h.SecureCookies})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	return nil
}
