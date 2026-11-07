// Package vault cifra dados pessoais com envelope encryption.
//
// Cada escopo/período (ex.: connection/2026-11) tem sua própria chave de dados
// (DEK), guardada no banco cifrada por uma chave de proteção (KEK) que nunca
// vai para o banco. Destruir a DEK de um período torna ilegível tudo o que foi
// cifrado com ela, inclusive em backups (crypto-shredding).
//
// Formato do texto cifrado: versão (1 byte) | id da DEK (4 bytes) | nonce | AES-256-GCM.
// O cabeçalho entra no AAD, então trocar o id da chave invalida a autenticação.
package vault

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Scope separa dados com ciclos de vida diferentes em chaves diferentes.
type Scope string

const (
	// ScopeConfig cifra segredos de configuração (ex.: senha do controlador). Nunca expira.
	ScopeConfig Scope = "config"
	// ScopeConnection cifra cadastros, sessões e logs. Uma chave por mês, sujeita à retenção.
	ScopeConnection Scope = "connection"
)

// Period devolve o período de chave usado para cifrar algo no instante at.
func Period(scope Scope, at time.Time) string {
	if scope == ScopeConfig {
		return "static"
	}
	return at.UTC().Format("2006-01")
}

var (
	ErrKeyNotFound  = errors.New("vault: chave não encontrada")
	ErrKeyDestroyed = errors.New("vault: chave destruída pela política de retenção")
	ErrMalformed    = errors.New("vault: texto cifrado inválido")
)

// KeyStore persiste as DEKs já cifradas pela KEK.
type KeyStore interface {
	FindKey(ctx context.Context, scope, period string) (id uint32, wrapped []byte, err error)
	// CreateKey grava a chave; se já existir uma para o período, devolve a existente.
	CreateKey(ctx context.Context, scope, period string, wrapped []byte) (id uint32, stored []byte, err error)
	GetKey(ctx context.Context, id uint32) (scope, period string, wrapped []byte, err error)
}

const (
	formatV1  byte = 1
	headerLen      = 5
	dekLen         = 32
)

type Vault struct {
	wrapper  Wrapper
	keys     KeyStore
	indexKey []byte

	mu       sync.RWMutex
	byID     map[uint32]cipher.AEAD
	byPeriod map[string]uint32
}

func New(w Wrapper, keys KeyStore, indexKey []byte) *Vault {
	return &Vault{
		wrapper:  w,
		keys:     keys,
		indexKey: indexKey,
		byID:     map[uint32]cipher.AEAD{},
		byPeriod: map[string]uint32{},
	}
}

// Seal cifra plaintext com a chave do escopo no período de at. O aad
// (dados associados) precisa ser o mesmo na hora de abrir; use-o para
// amarrar o texto cifrado ao seu contexto (ex.: "sessão", "log").
func (v *Vault) Seal(ctx context.Context, scope Scope, at time.Time, plaintext, aad []byte) ([]byte, error) {
	id, aead, err := v.currentKey(ctx, scope, Period(scope, at))
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	out := make([]byte, headerLen+ns, headerLen+ns+len(plaintext)+aead.Overhead())
	out[0] = formatV1
	binary.BigEndian.PutUint32(out[1:headerLen], id)
	if _, err := rand.Read(out[headerLen:]); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[headerLen:], plaintext, bindAAD(out[:headerLen], aad)), nil
}

func (v *Vault) Open(ctx context.Context, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < headerLen || ciphertext[0] != formatV1 {
		return nil, ErrMalformed
	}
	aead, err := v.keyByID(ctx, binary.BigEndian.Uint32(ciphertext[1:headerLen]))
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(ciphertext) < headerLen+ns+aead.Overhead() {
		return nil, ErrMalformed
	}
	pt, err := aead.Open(nil, ciphertext[headerLen:headerLen+ns], ciphertext[headerLen+ns:], bindAAD(ciphertext[:headerLen], aad))
	if err != nil {
		return nil, fmt.Errorf("vault: falha de autenticação: %w", err)
	}
	return pt, nil
}

// BlindIndex gera um identificador determinístico (HMAC-SHA256) para busca
// por igualdade sem guardar o valor. kind separa domínios: o mesmo valor em
// "mac" e em "field:email" gera índices diferentes. O valor deve chegar já
// normalizado.
func (v *Vault) BlindIndex(kind, value string) []byte {
	m := hmac.New(sha256.New, v.indexKey)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(value))
	return m.Sum(nil)[:16]
}

// Forget remove chaves destruídas do cache em memória.
func (v *Vault) Forget(ids ...uint32) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, id := range ids {
		delete(v.byID, id)
	}
	for k, id := range v.byPeriod {
		if slices.Contains(ids, id) {
			delete(v.byPeriod, k)
		}
	}
}

func (v *Vault) currentKey(ctx context.Context, scope Scope, period string) (uint32, cipher.AEAD, error) {
	cacheKey := string(scope) + "/" + period
	v.mu.RLock()
	id, ok := v.byPeriod[cacheKey]
	aead := v.byID[id]
	v.mu.RUnlock()
	if ok {
		return id, aead, nil
	}

	id, wrapped, err := v.keys.FindKey(ctx, string(scope), period)
	if errors.Is(err, ErrKeyNotFound) {
		dek := make([]byte, dekLen)
		if _, err := rand.Read(dek); err != nil {
			return 0, nil, err
		}
		w, werr := v.wrapper.Wrap(ctx, dek, dekAAD(string(scope), period))
		if werr != nil {
			return 0, nil, werr
		}
		id, wrapped, err = v.keys.CreateKey(ctx, string(scope), period, w)
	}
	if err != nil {
		return 0, nil, err
	}
	aead, err = v.unwrap(ctx, string(scope), period, wrapped)
	if err != nil {
		return 0, nil, err
	}

	v.mu.Lock()
	v.byPeriod[cacheKey] = id
	v.byID[id] = aead
	v.mu.Unlock()
	return id, aead, nil
}

func (v *Vault) keyByID(ctx context.Context, id uint32) (cipher.AEAD, error) {
	v.mu.RLock()
	aead, ok := v.byID[id]
	v.mu.RUnlock()
	if ok {
		return aead, nil
	}
	scope, period, wrapped, err := v.keys.GetKey(ctx, id)
	if err != nil {
		return nil, err
	}
	aead, err = v.unwrap(ctx, scope, period, wrapped)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.byID[id] = aead
	v.mu.Unlock()
	return aead, nil
}

func (v *Vault) unwrap(ctx context.Context, scope, period string, wrapped []byte) (cipher.AEAD, error) {
	dek, err := v.wrapper.Unwrap(ctx, wrapped, dekAAD(scope, period))
	if err != nil {
		return nil, fmt.Errorf("vault: não foi possível abrir a chave %s/%s (chave mestra errada?): %w", scope, period, err)
	}
	return newGCM(dek)
}

func dekAAD(scope, period string) []byte {
	return []byte("janus/dek/" + scope + "/" + period)
}

func bindAAD(header, aad []byte) []byte {
	b := make([]byte, 0, len(header)+len(aad))
	return append(append(b, header...), aad...)
}
