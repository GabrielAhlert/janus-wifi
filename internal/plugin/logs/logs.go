// Package logs define a interface dos parsers de syslog e o registro de
// drivers. Um parser novo (Sophos, pfSense, FortiGate...) só precisa
// implementar Parser, chamar Register num init() e ser importado em plugin/all.
package logs

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"janus/internal/core"
)

// Parser transforma uma linha de syslog num evento normalizado. ok=false
// significa que a linha não é relevante (não é tráfego nem DHCP).
type Parser interface {
	Parse(line string) (ev core.LogEvent, ok bool)
}

type Driver struct {
	Name  string // gravado no banco (ex.: "ucg")
	Label string // exibido no painel
	Help  string // como configurar o envio de syslog no equipamento
	New   func() Parser
}

var (
	mu      sync.RWMutex
	drivers = map[string]Driver{}
)

func Register(d Driver) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := drivers[d.Name]; dup {
		panic(fmt.Sprintf("logs: driver %q registrado duas vezes", d.Name))
	}
	drivers[d.Name] = d
}

func Lookup(name string) (Driver, bool) {
	mu.RLock()
	defer mu.RUnlock()
	d, ok := drivers[name]
	return d, ok
}

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
