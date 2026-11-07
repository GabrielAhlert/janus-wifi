package unifi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"janus/internal/plugin/wifi"
)

// fakeUniFiOS imita o login e o cmd/stamgr de um UCG.
type fakeUniFiOS struct {
	logins, commands int
	last             map[string]any
}

func (f *fakeUniFiOS) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["username"] != "hotspot" || body["password"] != "s3nha" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.logins++
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "abc", Path: "/"})
		w.Header().Set("X-Csrf-Token", "csrf-1")
		w.Write([]byte(`{}`))
	})
	mux.HandleFunc("POST /proxy/network/api/s/default/cmd/stamgr", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("TOKEN"); err != nil || c.Value != "abc" || r.Header.Get("X-Csrf-Token") != "csrf-1" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"meta":{"rc":"error","msg":"api.err.LoginRequired"}}`))
			return
		}
		f.commands++
		json.NewDecoder(r.Body).Decode(&f.last)
		w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	return mux
}

func newTestController(t *testing.T, srv *httptest.Server, fingerprint string) wifi.Controller {
	t.Helper()
	ctrl, err := New(map[string]string{
		"url": srv.URL, "username": "hotspot", "password": "s3nha",
		"unifi_os": "true", "tls_fingerprint": fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ctrl
}

func fingerprintOf(srv *httptest.Server) string {
	sum := sha256.Sum256(srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

func TestAuthorizeLogsInOnceAndReusesSession(t *testing.T) {
	fake := &fakeUniFiOS{}
	srv := httptest.NewTLSServer(fake.handler())
	defer srv.Close()
	ctrl := newTestController(t, srv, fingerprintOf(srv))

	client := wifi.Client{MAC: "aa:bb:cc:dd:ee:ff", APMAC: "11:22:33:44:55:66"}
	for range 2 {
		if err := ctrl.Authorize(context.Background(), client, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if fake.logins != 1 || fake.commands != 2 {
		t.Fatalf("logins=%d comandos=%d; esperado 1 login e 2 comandos", fake.logins, fake.commands)
	}
	if fake.last["cmd"] != "authorize-guest" || fake.last["mac"] != "aa:bb:cc:dd:ee:ff" || fake.last["minutes"] != float64(60) {
		t.Fatalf("corpo inesperado: %v", fake.last)
	}
}

func TestWrongPasswordFails(t *testing.T) {
	srv := httptest.NewTLSServer((&fakeUniFiOS{}).handler())
	defer srv.Close()
	ctrl, _ := New(map[string]string{"url": srv.URL, "username": "hotspot", "password": "errada", "unifi_os": "true", "tls_fingerprint": fingerprintOf(srv)})
	err := ctrl.Authorize(context.Background(), wifi.Client{MAC: "aa:bb:cc:dd:ee:ff"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "falha no login") {
		t.Fatalf("erro = %v, esperado falha no login", err)
	}
}

func TestFingerprintMismatchIsRejected(t *testing.T) {
	srv := httptest.NewTLSServer((&fakeUniFiOS{}).handler())
	defer srv.Close()
	ctrl := newTestController(t, srv, strings.Repeat("00", 32))
	err := ctrl.Authorize(context.Background(), wifi.Client{MAC: "aa:bb:cc:dd:ee:ff"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "certificado inesperado") {
		t.Fatalf("erro = %v, esperado certificado inesperado", err)
	}
}

func TestParseRedirect(t *testing.T) {
	ctrl, _ := New(map[string]string{"url": "https://192.168.1.1"})
	q, _ := url.ParseQuery("id=AA-BB-CC-DD-EE-FF&ap=11:22:33:44:55:66&t=1700000000&url=http%3A%2F%2Fexample.com%2F&ssid=Visitantes")
	c, err := ctrl.ParseRedirect(q)
	if err != nil {
		t.Fatal(err)
	}
	want := wifi.Client{MAC: "aa:bb:cc:dd:ee:ff", APMAC: "11:22:33:44:55:66", SSID: "Visitantes", RedirectURL: "http://example.com/"}
	if c != want {
		t.Fatalf("cliente = %+v, esperado %+v", c, want)
	}
	if _, err := ctrl.ParseRedirect(url.Values{}); err == nil {
		t.Fatal("redirecionamento sem id deveria falhar")
	}
}
