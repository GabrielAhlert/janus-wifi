// Package storetest é a suíte de contrato que todo driver de store.Store
// precisa passar. Cada driver a executa no seu próprio teste, com um banco
// novo e já migrado por subteste.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"janus/internal/core"
	"janus/internal/ingest"
	"janus/internal/store"
	"janus/internal/vault"
)

// Opener devolve um store vazio e migrado, fechado ao fim do teste.
type Opener func(t *testing.T) store.Store

func Run(t *testing.T, open Opener) {
	tests := []struct {
		name string
		fn   func(*testing.T, store.Store)
	}{
		{"Sites", testSites},
		{"Fields", testFields},
		{"Terms", testTerms},
		{"Sessions", testSessions},
		{"Keys", testKeys},
		{"Logs", testLogs},
		{"Admins", testAdmins},
		{"Settings", testSettings},
		{"MigrateIsIdempotent", testMigrateIdempotent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.fn(t, open(t)) })
	}
}

var ctx = context.Background()

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("erro = %v, esperado %v", err, target)
	}
}

func newSite(t *testing.T, s store.Store, slug string) core.Site {
	t.Helper()
	site := core.Site{Slug: slug, Name: "Site " + slug, SessionMinutes: 60, Theme: core.DefaultTheme(), ControllerSealed: []byte{1, 2, 3}}
	must(t, s.CreateSite(ctx, &site, core.DefaultFields(), core.DefaultTerms()))
	return site
}

func testSites(t *testing.T, s store.Store) {
	site := newSite(t, s, "matriz")
	if site.ID == 0 || site.UpdatedAt.IsZero() {
		t.Fatalf("CreateSite não preencheu id/updated_at: %+v", site)
	}
	wantErr(t, s.CreateSite(ctx, &core.Site{Slug: "matriz", Name: "Outro", SessionMinutes: 1, Theme: core.DefaultTheme()}, nil, core.DefaultTerms()), store.ErrConflict)

	got, err := s.SiteBySlug(ctx, "matriz")
	must(t, err)
	if got.ID != site.ID || got.Theme.Title != core.DefaultTheme().Title || !bytes.Equal(got.ControllerSealed, []byte{1, 2, 3}) {
		t.Fatalf("SiteBySlug = %+v", got)
	}

	before := got.UpdatedAt
	got.Name, got.Theme.Title, got.ControllerSealed = "Matriz SP", "Wi-Fi SP", nil
	must(t, s.UpdateSite(ctx, &got))
	again, err := s.Site(ctx, site.ID)
	must(t, err)
	if again.Name != "Matriz SP" || again.Theme.Title != "Wi-Fi SP" || again.ControllerSealed != nil || again.UpdatedAt.Before(before) {
		t.Fatalf("UpdateSite não persistiu: %+v", again)
	}

	newSite(t, s, "filial")
	list, err := s.Sites(ctx)
	must(t, err)
	if len(list) != 2 || list[0].Name != "Matriz SP" {
		t.Fatalf("Sites = %d itens, primeiro %q", len(list), list[0].Name)
	}

	_, err = s.Site(ctx, 99999)
	wantErr(t, err, store.ErrNotFound)
	wantErr(t, s.UpdateSite(ctx, &core.Site{ID: 99999, Slug: "x", Name: "x", Theme: core.DefaultTheme()}), store.ErrNotFound)
}

func testFields(t *testing.T, s store.Store) {
	site := newSite(t, s, "campos")
	fields, err := s.Fields(ctx, site.ID)
	must(t, err)
	if len(fields) != len(core.DefaultFields()) || fields[0].Key != "nome" || !fields[0].Required || fields[3].Enabled {
		t.Fatalf("Fields = %+v", fields)
	}

	f := core.Field{SiteID: site.ID, Key: "empresa", Label: "Empresa", Type: core.FieldText, Protection: core.ProtectPlain, Enabled: true, Position: 5}
	must(t, s.CreateField(ctx, &f))
	dup := f
	wantErr(t, s.CreateField(ctx, &dup), store.ErrConflict)

	fields, _ = s.Fields(ctx, site.ID)
	if fields[0].Key != "empresa" {
		t.Fatalf("ordem por posição não respeitada: primeiro = %q", fields[0].Key)
	}

	f.Label, f.Required, f.Protection = "Empresa onde trabalha", true, core.ProtectEncrypted
	must(t, s.UpdateField(ctx, f))
	got, err := s.Field(ctx, site.ID, f.ID)
	must(t, err)
	if got.Label != f.Label || !got.Required || got.Protection != core.ProtectEncrypted || got.Type != core.FieldText {
		t.Fatalf("UpdateField não persistiu: %+v", got)
	}

	must(t, s.DeleteField(ctx, site.ID, f.ID))
	_, err = s.Field(ctx, site.ID, f.ID)
	wantErr(t, err, store.ErrNotFound)
	wantErr(t, s.DeleteField(ctx, site.ID, f.ID), store.ErrNotFound)
}

func testTerms(t *testing.T, s store.Store) {
	site := newSite(t, s, "termos")
	cur, err := s.CurrentTerms(ctx, site.ID)
	must(t, err)
	if cur.Version != 1 || cur.Title != core.DefaultTerms().Title {
		t.Fatalf("CurrentTerms = %+v", cur)
	}

	must(t, s.CreateAdmin(ctx, "dpo@empresa.com", "hash"))
	admin, _, err := s.AdminCredentials(ctx, "dpo@empresa.com")
	must(t, err)
	v2, err := s.PublishTerms(ctx, site.ID, "Termos v2", "Texto novo", admin.ID)
	must(t, err)
	if v2.Version != 2 || v2.CreatedAt.IsZero() {
		t.Fatalf("PublishTerms = %+v", v2)
	}
	hist, err := s.TermsHistory(ctx, site.ID)
	must(t, err)
	if len(hist) != 2 || hist[0].Version != 2 || hist[1].Version != 1 {
		t.Fatalf("TermsHistory = %+v", hist)
	}
	if cur, _ = s.CurrentTerms(ctx, site.ID); cur.ID != v2.ID {
		t.Fatalf("versão vigente deveria ser a 2, é %d", cur.Version)
	}
}

func testSessions(t *testing.T, s store.Store) {
	site := newSite(t, s, "sessoes")
	terms, err := s.CurrentTerms(ctx, site.ID)
	must(t, err)
	created := time.Date(2026, 11, 6, 10, 0, 0, 123456000, time.UTC)
	rec := core.SessionRecord{
		SiteID: site.ID, TermsID: terms.ID, CreatedAt: created, ExpiresAt: created.Add(time.Hour),
		SSID: "Visitantes", Plain: map[string]string{"opt_in": "sim"}, Payload: []byte("cifrado"),
	}
	index := []core.IndexEntry{{Kind: core.IndexMAC, Value: []byte{1}}, {Kind: core.IndexMAC, Value: []byte{1}}}
	must(t, s.CreateSession(ctx, &rec, index))
	if rec.ID == 0 {
		t.Fatal("CreateSession não preencheu o id")
	}

	counts, err := s.SessionCountsSince(ctx, created.Add(-time.Minute))
	must(t, err)
	if counts[site.ID] != 1 {
		t.Fatalf("SessionCountsSince = %v", counts)
	}
	if counts, _ = s.SessionCountsSince(ctx, created.Add(time.Minute)); counts[site.ID] != 0 {
		t.Fatalf("SessionCountsSince depois da sessão = %v", counts)
	}

	sessions, _, err := s.DeleteConnectionDataBefore(ctx, created)
	must(t, err)
	if sessions != 0 {
		t.Fatalf("apagou %d sessões no limite exato; o corte deve ser exclusivo", sessions)
	}
	sessions, _, err = s.DeleteConnectionDataBefore(ctx, created.Add(time.Second))
	must(t, err)
	if sessions != 1 {
		t.Fatalf("DeleteConnectionDataBefore apagou %d sessões", sessions)
	}
}

func testKeys(t *testing.T, s store.Store) {
	has, err := s.HasDataKeys(ctx)
	must(t, err)
	if has {
		t.Fatal("banco novo não deveria ter chaves")
	}
	_, _, err = s.FindKey(ctx, "connection", "2026-11")
	wantErr(t, err, vault.ErrKeyNotFound)

	id, stored, err := s.CreateKey(ctx, "connection", "2026-11", []byte("chave-a"))
	must(t, err)
	// Em corrida, vale a chave que já estava no banco.
	id2, stored2, err := s.CreateKey(ctx, "connection", "2026-11", []byte("chave-b"))
	must(t, err)
	if id2 != id || string(stored) != "chave-a" || string(stored2) != "chave-a" {
		t.Fatalf("CreateKey repetido devolveu id=%d %q; esperado id=%d %q", id2, stored2, id, "chave-a")
	}
	scope, period, wrapped, err := s.GetKey(ctx, id)
	must(t, err)
	if scope != "connection" || period != "2026-11" || string(wrapped) != "chave-a" {
		t.Fatalf("GetKey = %s %s %q", scope, period, wrapped)
	}
	if has, _ = s.HasDataKeys(ctx); !has {
		t.Fatal("HasDataKeys deveria ser verdadeiro")
	}

	dec, _, err := s.CreateKey(ctx, "connection", "2026-12", []byte("chave-c"))
	must(t, err)
	cfg, _, err := s.CreateKey(ctx, "config", "static", []byte("chave-d"))
	must(t, err)

	destroyed, err := s.DestroyKeysBefore(ctx, "connection", "2026-12")
	must(t, err)
	if len(destroyed) != 1 || destroyed[0] != id {
		t.Fatalf("DestroyKeysBefore = %v, esperado [%d]", destroyed, id)
	}
	_, _, _, err = s.GetKey(ctx, id)
	wantErr(t, err, vault.ErrKeyDestroyed)
	_, _, err = s.FindKey(ctx, "connection", "2026-11")
	wantErr(t, err, vault.ErrKeyDestroyed)
	for _, kept := range []uint32{dec, cfg} {
		if _, _, _, err := s.GetKey(ctx, kept); err != nil {
			t.Fatalf("chave %d não deveria ter sido destruída: %v", kept, err)
		}
	}
	if again, _ := s.DestroyKeysBefore(ctx, "connection", "2026-12"); len(again) != 0 {
		t.Fatalf("destruir de novo deveria ser no-op, destruiu %v", again)
	}
}

func testLogs(t *testing.T, s store.Store) {
	src := core.LogSource{Name: "UCG", SenderIP: netip.MustParseAddr("192.168.1.1"), Parser: "ucg", Enabled: true}
	must(t, s.CreateLogSource(ctx, &src))
	dup := src
	wantErr(t, s.CreateLogSource(ctx, &dup), store.ErrConflict)
	sources, err := s.LogSources(ctx)
	must(t, err)
	if len(sources) != 1 || sources[0].SenderIP != src.SenderIP || !sources[0].Enabled {
		t.Fatalf("LogSources = %+v", sources)
	}

	last, err := s.LastLogHash(ctx)
	must(t, err)
	if last != nil {
		t.Fatalf("LastLogHash num banco vazio = %x", last)
	}

	// Microssegundos não redondos: a cadeia só fecha se a precisão for preservada.
	base := time.Date(2026, 11, 6, 10, 0, 0, 987654000, time.UTC)
	prev := make([]byte, 32)
	var recs []core.LogRecord
	for i := range 3 {
		r := core.LogRecord{ReceivedAt: base.Add(time.Duration(i) * time.Second), SourceID: src.ID, SrcIPIndex: []byte{byte(i)}, Payload: []byte("cifrado"), PrevHash: prev}
		if i == 1 {
			r.SrcMACIndex = []byte{9}
		}
		r.Hash = ingest.HashRecord(prev, r)
		prev = r.Hash
		recs = append(recs, r)
	}
	must(t, s.InsertLogEvents(ctx, recs))

	if last, _ = s.LastLogHash(ctx); !bytes.Equal(last, prev) {
		t.Fatal("LastLogHash não é o hash do último evento do lote")
	}
	rep, err := ingest.Verify(ctx, s.ScanLogEvents)
	must(t, err)
	if rep.Records != 3 || rep.FirstID >= rep.LastID {
		t.Fatalf("Verify = %+v", rep)
	}
	n, err := s.LogEventCountSince(ctx, base.Add(500*time.Millisecond))
	must(t, err)
	if n != 2 {
		t.Fatalf("LogEventCountSince = %d, esperado 2", n)
	}

	_, events, err := s.DeleteConnectionDataBefore(ctx, base.Add(time.Second))
	must(t, err)
	if events != 1 {
		t.Fatalf("apagou %d eventos, esperado 1", events)
	}
	if _, err := ingest.Verify(ctx, s.ScanLogEvents); err != nil {
		t.Fatalf("a cadeia deveria continuar válida após a retenção: %v", err)
	}

	must(t, s.DeleteLogSource(ctx, src.ID))
	wantErr(t, s.DeleteLogSource(ctx, src.ID), store.ErrNotFound)
}

func testAdmins(t *testing.T, s store.Store) {
	must(t, s.CreateAdmin(ctx, "ti@empresa.com", "hash-1"))
	wantErr(t, s.CreateAdmin(ctx, "ti@empresa.com", "hash-2"), store.ErrConflict)
	a, hash, err := s.AdminCredentials(ctx, "ti@empresa.com")
	must(t, err)
	if hash != "hash-1" || a.Email != "ti@empresa.com" || a.CreatedAt.IsZero() {
		t.Fatalf("AdminCredentials = %+v %q", a, hash)
	}
	_, _, err = s.AdminCredentials(ctx, "ninguem@empresa.com")
	wantErr(t, err, store.ErrNotFound)

	must(t, s.CreateAdminSession(ctx, []byte("valida"), a.ID, time.Now().Add(time.Hour)))
	must(t, s.CreateAdminSession(ctx, []byte("expirada"), a.ID, time.Now().Add(-time.Minute)))
	if got, err := s.AdminBySession(ctx, []byte("valida")); err != nil || got.ID != a.ID {
		t.Fatalf("AdminBySession = %+v, %v", got, err)
	}
	_, err = s.AdminBySession(ctx, []byte("expirada"))
	wantErr(t, err, store.ErrNotFound)
	must(t, s.DeleteAdminSession(ctx, []byte("valida")))
	_, err = s.AdminBySession(ctx, []byte("valida"))
	wantErr(t, err, store.ErrNotFound)

	must(t, s.Audit(ctx, a.ID, "login", map[string]string{"ip": "10.0.0.1"}))

	id, err := s.CreateAsset(ctx, "image/png", []byte{0x89, 'P', 'N', 'G'})
	must(t, err)
	mime, data, err := s.Asset(ctx, id)
	must(t, err)
	if mime != "image/png" || !bytes.Equal(data, []byte{0x89, 'P', 'N', 'G'}) {
		t.Fatalf("Asset = %s %x", mime, data)
	}
	_, _, err = s.Asset(ctx, id+1000)
	wantErr(t, err, store.ErrNotFound)
}

func testSettings(t *testing.T, s store.Store) {
	months, err := s.RetentionMonths(ctx)
	must(t, err)
	if months != store.DefaultRetentionMonths {
		t.Fatalf("retenção padrão = %d", months)
	}
	must(t, s.SetRetentionMonths(ctx, 24))
	must(t, s.SetRetentionMonths(ctx, 18))
	if months, _ = s.RetentionMonths(ctx); months != 18 {
		t.Fatalf("retenção = %d, esperado 18", months)
	}
}

func testMigrateIdempotent(t *testing.T, s store.Store) {
	must(t, s.Migrate(ctx))
	must(t, s.Migrate(ctx))
	if s.Describe() == "" {
		t.Fatal("Describe vazio")
	}
}
