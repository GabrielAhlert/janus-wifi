package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Keys são as chaves derivadas da chave mestra, uma por finalidade: vazar o
// índice cego não compromete a cifra, e vice-versa.
type Keys struct {
	Wrap  []byte // protege as DEKs
	Index []byte // HMAC dos índices cegos
	Token []byte // assinatura dos tickets do portal
}

func DeriveKeys(master []byte) (Keys, error) {
	if len(master) != 32 {
		return Keys{}, errors.New("vault: a chave mestra deve ter 32 bytes")
	}
	var k Keys
	targets := []struct {
		label string
		dst   *[]byte
	}{{"wrap", &k.Wrap}, {"index", &k.Index}, {"token", &k.Token}}
	for _, t := range targets {
		key, err := hkdf.Key(sha256.New, master, nil, "janus/"+t.label, 32)
		if err != nil {
			return Keys{}, err
		}
		*t.dst = key
	}
	return k, nil
}

// GenerateMasterKey cria uma chave mestra nova, em base64.
func GenerateMasterKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// Wrapper protege as DEKs. A implementação local usa AES-256-GCM com uma
// chave derivada da chave mestra; um KMS ou HashiCorp Vault pode
// substituí-la implementando esta mesma interface.
type Wrapper interface {
	Wrap(ctx context.Context, dek, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
}

type localWrapper struct{ aead cipher.AEAD }

func NewLocalWrapper(key []byte) (Wrapper, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return localWrapper{aead}, nil
}

func (w localWrapper) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	nonce := make([]byte, w.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return w.aead.Seal(nonce, nonce, dek, aad), nil
}

func (w localWrapper) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	ns := w.aead.NonceSize()
	if len(wrapped) < ns {
		return nil, ErrMalformed
	}
	return w.aead.Open(nil, wrapped[:ns], wrapped[ns:], aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
