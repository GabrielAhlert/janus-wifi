package portal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrInvalidToken = errors.New("token inválido ou expirado")

// Signer assina dados com HMAC para que voltem intactos do navegador.
type Signer struct{ key []byte }

func NewSigner(key []byte) Signer { return Signer{key: key} }

func (s Signer) Sign(data any, ttl time.Duration) (string, error) {
	body, err := json.Marshal(struct {
		Exp  int64 `json:"exp"`
		Data any   `json:"d"`
	}{time.Now().Add(ttl).Unix(), data})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(body)
	return enc + "." + base64.RawURLEncoding.EncodeToString(s.mac(enc)), nil
}

func (s Signer) Verify(token string, out any) error {
	enc, sig, ok := strings.Cut(token, ".")
	if !ok {
		return ErrInvalidToken
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(enc)) {
		return ErrInvalidToken
	}
	body, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return ErrInvalidToken
	}
	var env struct {
		Exp  int64           `json:"exp"`
		Data json.RawMessage `json:"d"`
	}
	if err := json.Unmarshal(body, &env); err != nil || time.Now().Unix() > env.Exp {
		return ErrInvalidToken
	}
	return json.Unmarshal(env.Data, out)
}

func (s Signer) mac(msg string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}
