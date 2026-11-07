package portal

import (
	"strings"
	"testing"
	"time"

	"janus/internal/plugin/wifi"
)

func TestSignerRoundTrip(t *testing.T) {
	s := NewSigner([]byte("chave-de-teste-com-32-bytes-.."))
	in := ticket{SiteID: 7, Client: wifi.Client{MAC: "aa:bb:cc:dd:ee:ff"}}
	tok, err := s.Sign(in, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var out ticket
	if err := s.Verify(tok, &out); err != nil || out != in {
		t.Fatalf("Verify = %+v, %v", out, err)
	}
}

func TestSignerRejectsTamperingAndExpiry(t *testing.T) {
	s := NewSigner([]byte("k"))
	tok, _ := s.Sign(ticket{SiteID: 1}, time.Minute)
	enc, sig, _ := strings.Cut(tok, ".")
	forged, _ := NewSigner([]byte("outra")).Sign(ticket{SiteID: 2}, time.Minute)

	expired, _ := s.Sign(ticket{SiteID: 1}, -time.Second)
	for name, bad := range map[string]string{
		"assinatura":  enc + "." + sig[:len(sig)-2] + "AA",
		"outra chave": forged,
		"expirado":    expired,
		"lixo":        "abc",
	} {
		if err := s.Verify(bad, &ticket{}); err == nil {
			t.Errorf("%s: deveria falhar", name)
		}
	}
}
