// Package hotspot implementa o caso de uso central: validar o cadastro do
// visitante, gravá-lo cifrado e pedir ao controlador que libere o acesso.
package hotspot

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"janus/internal/core"
	"janus/internal/plugin/wifi"
	"janus/internal/sites"
	"janus/internal/store"
	"janus/internal/vault"
)

var sessionAAD = []byte("janus/session")

type Service struct {
	db    store.Store
	vault *vault.Vault
	sites *sites.Service
	log   *slog.Logger
}

func New(db store.Store, v *vault.Vault, s *sites.Service, log *slog.Logger) *Service {
	return &Service{db: db, vault: v, sites: s, log: log}
}

type Request struct {
	Site          core.Site
	Client        wifi.Client
	ClientIP      string
	UserAgent     string
	Values        map[string]string // valores crus do formulário, por chave de campo
	AcceptedTerms bool
}

// ValidationError traz mensagens que podem ser mostradas ao visitante.
type ValidationError struct{ Messages []string }

func (e *ValidationError) Error() string { return strings.Join(e.Messages, "; ") }

// EnabledFields devolve os campos que aparecem no portal.
func (s *Service) EnabledFields(ctx context.Context, siteID int64) ([]core.Field, error) {
	all, err := s.db.Fields(ctx, siteID)
	if err != nil {
		return nil, err
	}
	var out []core.Field
	for _, f := range all {
		if f.Enabled {
			out = append(out, f)
		}
	}
	return out, nil
}

func (s *Service) Connect(ctx context.Context, req Request) (core.SessionRecord, error) {
	fields, err := s.EnabledFields(ctx, req.Site.ID)
	if err != nil {
		return core.SessionRecord{}, err
	}
	terms, err := s.db.CurrentTerms(ctx, req.Site.ID)
	if err != nil {
		return core.SessionRecord{}, fmt.Errorf("termos vigentes: %w", err)
	}
	ctrl, err := s.sites.Controller(req.Site)
	if err != nil {
		return core.SessionRecord{}, err
	}

	values := map[string]string{}
	var problems []string
	for _, f := range fields {
		v, err := f.Normalize(req.Values[f.Key])
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if v != "" {
			values[f.Key] = v
		}
	}
	if !req.AcceptedTerms {
		problems = append(problems, "É preciso aceitar os termos de uso.")
	}
	if len(problems) > 0 {
		return core.SessionRecord{}, &ValidationError{problems}
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	rec := core.SessionRecord{
		SiteID:    req.Site.ID,
		TermsID:   terms.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(req.Site.SessionMinutes) * time.Minute),
		SSID:      req.Client.SSID,
		Plain:     map[string]string{},
	}
	payload := core.SessionPayload{
		Client: core.ClientInfo{MAC: req.Client.MAC, APMAC: req.Client.APMAC, IP: core.NormalizeIP(req.ClientIP), UserAgent: req.UserAgent},
		Fields: map[string]string{},
	}
	index := []core.IndexEntry{s.index(core.IndexMAC, req.Client.MAC)}
	if payload.Client.IP != "" {
		index = append(index, s.index(core.IndexIP, payload.Client.IP))
	}
	for _, f := range fields {
		v, ok := values[f.Key]
		if !ok {
			continue
		}
		if f.Protection == core.ProtectPlain {
			rec.Plain[f.Key] = v
			continue
		}
		payload.Fields[f.Key] = v
		if f.Protection == core.ProtectIndexed {
			index = append(index, s.index(core.FieldIndex(f.Key), v))
		}
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return rec, err
	}
	if rec.Payload, err = s.vault.Seal(ctx, vault.ScopeConnection, now, plaintext, sessionAAD); err != nil {
		return rec, err
	}
	// Grava antes de liberar: ninguém navega sem que a sessão esteja registrada.
	if err := s.db.CreateSession(ctx, &rec, index); err != nil {
		return rec, fmt.Errorf("gravar sessão: %w", err)
	}
	if err := ctrl.Authorize(ctx, req.Client, time.Duration(req.Site.SessionMinutes)*time.Minute); err != nil {
		return rec, fmt.Errorf("autorizar no controlador: %w", err)
	}
	s.log.Info("visitante autorizado", "site", req.Site.Slug, "sessao", rec.ID)
	return rec, nil
}

func (s *Service) index(kind, value string) core.IndexEntry {
	return core.IndexEntry{Kind: kind, Value: s.vault.BlindIndex(kind, value)}
}
