package admin

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestAllowNets(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("10.0.0.7/32")}

	tests := []struct {
		nets   []netip.Prefix
		remote string
		want   int
	}{
		{lan, "192.168.1.25:51000", http.StatusOK},
		{lan, "10.0.0.7:51000", http.StatusOK},
		{lan, "[::ffff:192.168.1.25]:51000", http.StatusOK},
		{lan, "192.168.20.15:51000", http.StatusForbidden}, // rede de visitantes
		{lan, "10.0.0.8:51000", http.StatusForbidden},
		{nil, "192.168.20.15:51000", http.StatusOK}, // sem lista, tudo liberado
	}
	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = tt.remote
		w := httptest.NewRecorder()
		allowNets(tt.nets, ok).ServeHTTP(w, r)
		if w.Code != tt.want {
			t.Errorf("%s com %v: status %d, esperado %d", tt.remote, tt.nets, w.Code, tt.want)
		}
	}
}
