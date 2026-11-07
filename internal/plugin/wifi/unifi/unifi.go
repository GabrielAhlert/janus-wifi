// Package unifi integra o Janus como External Portal de controladores
// Ubiquiti UniFi (UniFi OS: UCG, UDM, Cloud Key Gen2+; ou controlador legado).
//
// Fluxo: o UniFi redireciona o visitante para /guest/s/<site>/?id=<mac>&ap=...
// e, depois do cadastro, o Janus chama cmd/stamgr "authorize-guest" na API.
package unifi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"janus/internal/core"
	"janus/internal/plugin"
	"janus/internal/plugin/wifi"
)

func init() {
	wifi.Register(wifi.Driver{
		Name:    "unifi",
		Label:   "Ubiquiti UniFi",
		Config:  configFields,
		New:     New,
		Prepare: prepare,
	})
}

var configFields = []plugin.ConfigField{
	{Key: "url", Label: "Endereço do controlador", Type: plugin.Text, Required: true,
		Help: "Ex.: 192.168.1.1 (UCG/UDM) ou https://controller:8443 (legado); sem esquema, usa https"},
	{Key: "site", Label: "Site no UniFi", Type: plugin.Text, Default: "default",
		Help: "Nome curto do site, como aparece na URL do controlador"},
	{Key: "username", Label: "Usuário", Type: plugin.Text, Required: true,
		Help: "Conta local dedicada, de preferência com a função Hotspot Operator"},
	{Key: "password", Label: "Senha", Type: plugin.Password, Required: true, Secret: true},
	{Key: "unifi_os", Label: "UniFi OS (UCG, UDM, Cloud Key Gen2+)", Type: plugin.Bool, Default: "true"},
	{Key: "tls_fingerprint", Label: "Fingerprint SHA-256 do certificado", Type: plugin.Text,
		Help: "Em branco, o Janus lê o certificado ao salvar e, se for autoassinado (o padrão do UniFi), preenche este campo"},
}

type Controller struct {
	base     *url.URL
	site     string
	username string
	password string
	unifiOS  bool
	http     *http.Client

	mu   sync.Mutex
	csrf string
}

func New(cfg map[string]string) (wifi.Controller, error) {
	base, err := parseBase(cfg["url"])
	if err != nil {
		return nil, err
	}
	tlsCfg, err := tlsConfig(cfg["tls_fingerprint"])
	if err != nil {
		return nil, err
	}
	jar, _ := cookiejar.New(nil)
	site := cfg["site"]
	if site == "" {
		site = "default"
	}
	return &Controller{
		base:     base,
		site:     site,
		username: cfg["username"],
		password: cfg["password"],
		unifiOS:  cfg["unifi_os"] == "true",
		http: &http.Client{
			Timeout:   10 * time.Second,
			Jar:       jar,
			Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
		},
	}, nil
}

// parseBase aceita a URL completa ou só o host ("192.168.1.1",
// "controller:8443"); sem esquema, assume https, que é o que o UniFi usa.
func parseBase(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	raw = strings.TrimRight(raw, "/")
	base, err := url.Parse(raw)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Hostname() == "" {
		return nil, fmt.Errorf("endereço do controlador inválido: %q (ex.: https://192.168.1.1)", raw)
	}
	return base, nil
}

func (c *Controller) ParseRedirect(q url.Values) (wifi.Client, error) {
	mac, err := core.NormalizeMAC(q.Get("id"))
	if err != nil {
		return wifi.Client{}, errors.New("unifi: redirecionamento sem MAC do cliente (parâmetro id)")
	}
	ap, _ := core.NormalizeMAC(q.Get("ap")) // opcional
	return wifi.Client{MAC: mac, APMAC: ap, SSID: q.Get("ssid"), RedirectURL: q.Get("url")}, nil
}

func (c *Controller) Authorize(ctx context.Context, cl wifi.Client, d time.Duration) error {
	body := map[string]any{
		"cmd":     "authorize-guest",
		"mac":     cl.MAC,
		"minutes": max(1, int(d.Minutes())),
	}
	if cl.APMAC != "" {
		body["ap_mac"] = cl.APMAC
	}
	return c.call(ctx, c.apiPath("cmd/stamgr"), body)
}

func (c *Controller) Deauthorize(ctx context.Context, mac string) error {
	return c.call(ctx, c.apiPath("cmd/stamgr"), map[string]any{"cmd": "unauthorize-guest", "mac": mac})
}

// apiPath monta o caminho da API clássica; no UniFi OS ela fica sob /proxy/network.
func (c *Controller) apiPath(p string) string {
	prefix := ""
	if c.unifiOS {
		prefix = "/proxy/network"
	}
	return prefix + "/api/s/" + url.PathEscape(c.site) + "/" + p
}

// call faz o POST e, se a sessão tiver expirado (401), autentica e tenta de novo.
func (c *Controller) call(ctx context.Context, path string, body any) error {
	for attempt := 0; ; attempt++ {
		resp, err := c.send(ctx, path, body)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if err := c.login(ctx); err != nil {
				return err
			}
			continue
		}
		if err := checkResponse(resp); err != nil {
			return fmt.Errorf("unifi: %w", err)
		}
		return nil
	}
}

func (c *Controller) login(ctx context.Context) error {
	path := "/api/login"
	if c.unifiOS {
		path = "/api/auth/login"
	}
	resp, err := c.send(ctx, path, map[string]any{"username": c.username, "password": c.password, "remember": true})
	if err != nil {
		return err
	}
	if t := resp.Header.Get("X-Csrf-Token"); t != "" {
		c.setCSRF(t)
	}
	if err := checkResponse(resp); err != nil {
		return fmt.Errorf("unifi: falha no login: %w", err)
	}
	return nil
}

func (c *Controller) send(ctx context.Context, path string, body any) (*http.Response, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.JoinPath(path).String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.mu.Lock()
	if c.csrf != "" {
		req.Header.Set("X-Csrf-Token", c.csrf)
	}
	c.mu.Unlock()

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unifi: %w", err)
	}
	// O UniFi OS rotaciona o token CSRF em algumas respostas.
	if t := resp.Header.Get("X-Updated-Csrf-Token"); t != "" {
		c.setCSRF(t)
	}
	return resp, nil
}

func (c *Controller) setCSRF(t string) {
	c.mu.Lock()
	c.csrf = t
	c.mu.Unlock()
}

// checkResponse valida o status HTTP e o envelope {"meta":{"rc":"ok"}} da API clássica.
func checkResponse(resp *http.Response) error {
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env struct {
		Meta struct {
			RC  string `json:"rc"`
			Msg string `json:"msg"`
		} `json:"meta"`
	}
	_ = json.Unmarshal(data, &env)
	if resp.StatusCode < 300 && (env.Meta.RC == "" || env.Meta.RC == "ok") {
		return nil
	}
	msg := env.Meta.Msg
	if msg == "" {
		msg = strings.TrimSpace(string(data))
		if len(msg) > 200 {
			msg = msg[:200]
		}
	}
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
}

// prepare fixa o certificado do controlador quando ele não é confiável pelo
// sistema (autoassinado) e o fingerprint está em branco. Se o controlador não
// responder, salva assim mesmo: o erro aparece ao liberar o primeiro visitante.
func prepare(ctx context.Context, cfg map[string]string) (map[string]string, error) {
	if strings.TrimSpace(cfg["tls_fingerprint"]) != "" {
		return cfg, nil
	}
	base, err := parseBase(cfg["url"])
	if err != nil || base.Scheme != "https" {
		return cfg, err
	}
	fp, err := untrustedFingerprint(ctx, base)
	if err != nil || fp == "" {
		return cfg, nil
	}
	out := maps.Clone(cfg)
	out["tls_fingerprint"] = fp
	return out, nil
}

// untrustedFingerprint conecta no controlador e devolve o SHA-256 do
// certificado se a validação padrão o recusar, ou "" se ele for confiável.
func untrustedFingerprint(ctx context.Context, base *url.URL) (string, error) {
	addr := base.Host
	if base.Port() == "" {
		addr = net.JoinHostPort(base.Hostname(), "443")
	}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: base.Hostname()},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		conn.Close()
		return "", nil
	}
	var verr *tls.CertificateVerificationError
	if !errors.As(err, &verr) || len(verr.UnverifiedCertificates) == 0 {
		return "", err
	}
	sum := sha256.Sum256(verr.UnverifiedCertificates[0].Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":"), nil
}

func tlsConfig(fingerprint string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	fp := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(fingerprint))
	if fp == "" {
		return cfg, nil
	}
	want, err := hex.DecodeString(fp)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("unifi: o fingerprint deve ser um SHA-256 em hexadecimal")
	}
	// Controladores UniFi costumam usar certificado autoassinado. Em vez de
	// desligar a verificação, aceitamos apenas o certificado com este fingerprint.
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("unifi: o controlador não apresentou certificado")
		}
		got := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return fmt.Errorf("unifi: certificado inesperado (fingerprint %x)", got)
		}
		return nil
	}
	return cfg, nil
}
