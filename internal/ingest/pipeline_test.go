package ingest

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"janus/internal/core"
	_ "janus/internal/plugin/logs/ucg"
	"janus/internal/vault"
)

// fakeStore guarda tudo em memória e também serve de KeyStore do vault.
type fakeStore struct {
	mu      sync.Mutex
	sources []core.LogSource
	events  []core.LogRecord
	key     []byte
}

func (f *fakeStore) LogSources(context.Context) ([]core.LogSource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]core.LogSource(nil), f.sources...), nil
}

func (f *fakeStore) LastLogHash(context.Context) ([]byte, error) { return nil, nil }

func (f *fakeStore) InsertLogEvents(_ context.Context, recs []core.LogRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, recs...)
	return nil
}

func (f *fakeStore) stored() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func (f *fakeStore) FindKey(context.Context, string, string) (uint32, []byte, error) {
	if f.key == nil {
		return 0, nil, vault.ErrKeyNotFound
	}
	return 1, f.key, nil
}

func (f *fakeStore) CreateKey(_ context.Context, _, _ string, w []byte) (uint32, []byte, error) {
	f.key = w
	return 1, w, nil
}

func (f *fakeStore) GetKey(context.Context, uint32) (string, string, []byte, error) {
	return "connection", time.Now().UTC().Format("2006-01"), f.key, nil
}

func TestReloadAppliesNewSourceImmediately(t *testing.T) {
	keys, _ := vault.DeriveKeys(make([]byte, 32))
	w, _ := vault.NewLocalWrapper(keys.Wrap)
	st := &fakeStore{}
	p := New(st, vault.New(w, st, keys.Index), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	ucg := netip.MustParseAddr("192.168.1.1")
	line := "kernel: [GUEST_IN-A-2000] SRC=192.168.20.15 DST=1.1.1.1 PROTO=UDP SPT=5353 DPT=53"

	// Fonte cadastrada depois do início: sem Reload, só valeria no próximo ciclo (30 s).
	st.mu.Lock()
	st.sources = []core.LogSource{{ID: 1, Name: "UCG", SenderIP: ucg, Parser: "ucg", Enabled: true}}
	st.mu.Unlock()
	p.Reload()

	deadline := time.Now().Add(5 * time.Second)
	for st.stored() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("evento não gravado após Reload; stats=%+v", p.Stats())
		}
		if p.Stats().Stored == 0 && p.Stats().Queued == 0 {
			p.Handle(ucg, line)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if refreshEvery < 5*time.Second {
		t.Fatal("o teste só prova algo se o ciclo periódico for mais lento que o prazo")
	}
}

func TestUnknownSenderWarnedOncePerIP(t *testing.T) {
	var out bytes.Buffer
	p := New(&fakeStore{}, nil, slog.New(slog.NewTextHandler(&out, nil)))
	a, b := netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("192.168.1.2")
	for range 3 {
		p.Handle(a, "x")
	}
	p.Handle(b, "x")

	if got := p.Stats().Unknown; got != 4 {
		t.Fatalf("Unknown = %d, quer 4", got)
	}
	log := out.String()
	if n := strings.Count(log, "ip=192.168.1.1"); n != 1 {
		t.Fatalf("aviso de 192.168.1.1 apareceu %d vezes, quer 1:\n%s", n, log)
	}
	if !strings.Contains(log, "ip=192.168.1.2") {
		t.Fatalf("faltou o aviso de 192.168.1.2:\n%s", log)
	}
}
