// Package wifi define a interface dos controladores Wi-Fi e o registro de
// drivers. Um driver novo (Aruba, MikroTik, Omada...) só precisa implementar
// Controller, chamar Register num init() e ser importado em plugin/all.
package wifi

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"janus/internal/plugin"
)

// Client é o dispositivo que o controlador redirecionou para o portal.
type Client struct {
	MAC         string `json:"mac"`
	APMAC       string `json:"ap,omitempty"`
	SSID        string `json:"ssid,omitempty"`
	RedirectURL string `json:"url,omitempty"` // página que o visitante tentou abrir
}

type Controller interface {
	// ParseRedirect lê os parâmetros com que o controlador manda o cliente ao portal.
	ParseRedirect(q url.Values) (Client, error)
	// Authorize libera o cliente por d.
	Authorize(ctx context.Context, c Client, d time.Duration) error
	// Deauthorize revoga o acesso do MAC.
	Deauthorize(ctx context.Context, mac string) error
}

type Driver struct {
	Name   string // identificador gravado no banco (ex.: "unifi")
	Label  string // nome exibido no painel
	Config []plugin.ConfigField
	New    func(cfg map[string]string) (Controller, error)
	// Prepare, opcional, completa a configuração quando o administrador salva
	// (ex.: fixar o certificado autoassinado do controlador). Devolve a
	// configuração a gravar.
	Prepare func(ctx context.Context, cfg map[string]string) (map[string]string, error)
}

var (
	mu      sync.RWMutex
	drivers = map[string]Driver{}
)

func Register(d Driver) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := drivers[d.Name]; dup {
		panic(fmt.Sprintf("wifi: driver %q registrado duas vezes", d.Name))
	}
	drivers[d.Name] = d
}

func Lookup(name string) (Driver, bool) {
	mu.RLock()
	defer mu.RUnlock()
	d, ok := drivers[name]
	return d, ok
}

// Drivers devolve os drivers registrados, em ordem alfabética.
func Drivers() []Driver {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Driver, 0, len(drivers))
	for _, d := range drivers {
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b Driver) int { return strings.Compare(a.Label, b.Label) })
	return out
}
