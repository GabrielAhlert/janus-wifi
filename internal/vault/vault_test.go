package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"
)

type memKey struct {
	scope, period string
	wrapped       []byte
}

type memKeys struct {
	mu   sync.Mutex
	rows map[uint32]*memKey
}

func (m *memKeys) FindKey(_ context.Context, scope, period string) (uint32, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, k := range m.rows {
		if k.scope == scope && k.period == period {
			if k.wrapped == nil {
				return 0, nil, ErrKeyDestroyed
			}
			return id, k.wrapped, nil
		}
	}
	return 0, nil, ErrKeyNotFound
}

func (m *memKeys) CreateKey(ctx context.Context, scope, period string, wrapped []byte) (uint32, []byte, error) {
	if id, w, err := m.FindKey(ctx, scope, period); err == nil {
		return id, w, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uint32(len(m.rows) + 1)
	m.rows[id] = &memKey{scope, period, wrapped}
	return id, wrapped, nil
}

func (m *memKeys) GetKey(_ context.Context, id uint32) (string, string, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.rows[id]
	if !ok {
		return "", "", nil, ErrKeyNotFound
	}
	if k.wrapped == nil {
		return "", "", nil, ErrKeyDestroyed
	}
	return k.scope, k.period, k.wrapped, nil
}

func newTestVault(t *testing.T) (*Vault, *memKeys) {
	t.Helper()
	master := make([]byte, 32)
	rand.Read(master)
	keys, err := DeriveKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewLocalWrapper(keys.Wrap)
	if err != nil {
		t.Fatal(err)
	}
	store := &memKeys{rows: map[uint32]*memKey{}}
	return New(w, store, keys.Index), store
}

func TestSealOpen(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	ct, err := v.Seal(ctx, ScopeConnection, time.Now(), []byte("cpf 529.982.247-25"), []byte("sessao"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("529")) {
		t.Fatal("texto cifrado contém o texto puro")
	}
	pt, err := v.Open(ctx, ct, []byte("sessao"))
	if err != nil || string(pt) != "cpf 529.982.247-25" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	if _, err := v.Open(ctx, ct, []byte("log")); err == nil {
		t.Fatal("Open com AAD diferente deveria falhar")
	}
	ct[len(ct)-1] ^= 1
	if _, err := v.Open(ctx, ct, []byte("sessao")); err == nil {
		t.Fatal("Open de texto adulterado deveria falhar")
	}
}

func TestKeyPerMonth(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	nov, _ := v.Seal(ctx, ScopeConnection, time.Date(2026, 11, 30, 23, 0, 0, 0, time.UTC), []byte("a"), nil)
	dec, _ := v.Seal(ctx, ScopeConnection, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC), []byte("b"), nil)
	if binary.BigEndian.Uint32(nov[1:5]) == binary.BigEndian.Uint32(dec[1:5]) {
		t.Fatal("meses diferentes deveriam usar chaves diferentes")
	}
}

func TestCryptoShredding(t *testing.T) {
	v, store := newTestVault(t)
	ctx := context.Background()
	ct, _ := v.Seal(ctx, ScopeConnection, time.Now(), []byte("dado"), nil)
	id := binary.BigEndian.Uint32(ct[1:5])

	store.rows[id].wrapped = nil
	v.Forget(id)

	if _, err := v.Open(ctx, ct, nil); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("Open após destruir a chave: %v, esperado ErrKeyDestroyed", err)
	}
}

func TestOpenWithDifferentMasterKeyFails(t *testing.T) {
	a, store := newTestVault(t)
	b, _ := newTestVault(t)
	b.keys = store // mesmo banco, chave mestra diferente
	ct, _ := a.Seal(context.Background(), ScopeConfig, time.Now(), []byte("senha"), nil)
	if _, err := b.Open(context.Background(), ct, nil); err == nil {
		t.Fatal("outra chave mestra não deveria abrir os dados")
	}
}

func TestBlindIndex(t *testing.T) {
	v, _ := newTestVault(t)
	if !bytes.Equal(v.BlindIndex("mac", "aa:bb:cc:dd:ee:ff"), v.BlindIndex("mac", "aa:bb:cc:dd:ee:ff")) {
		t.Fatal("o índice deveria ser determinístico")
	}
	if bytes.Equal(v.BlindIndex("mac", "x"), v.BlindIndex("ip", "x")) {
		t.Fatal("tipos diferentes deveriam gerar índices diferentes")
	}
}
