// Package ucg interpreta o syslog de gateways UniFi (UCG, UDM, UXG):
//   - regras de firewall com log ligado (formato iptables: [LAN_IN-A-3000] SRC=... DPT=...)
//   - eventos no formato CEF (UniFi Network 9+: src=... dpt=...)
//   - concessões DHCP do dnsmasq (DHCPACK(br0) 192.168.1.50 aa:bb:...), que
//     ligam IP a MAC
package ucg

import (
	"regexp"
	"strconv"
	"strings"

	"janus/internal/core"
	"janus/internal/plugin/logs"
	"janus/internal/plugin/logs/kv"
)

func init() {
	logs.Register(logs.Driver{
		Name:  "ucg",
		Label: "UniFi Gateway (UCG, UDM, UXG)",
		Help:  "No UniFi Network: Settings → Control Plane → Integrations → Activity Logging (SIEM), apontando para este servidor na porta de syslog. Ligue o log nas regras de firewall da rede de visitantes.",
		New:   func() logs.Parser { return parser{} },
	})
}

var (
	ruleRe = regexp.MustCompile(`\[([A-Za-z0-9_]+-([ADR])-[^\]\s]*)\]`)
	dhcpRe = regexp.MustCompile(`DHCPACK\([^)]*\)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f:]{17})`)
)

var ruleActions = map[string]string{"A": "accept", "D": "drop", "R": "reject"}

type parser struct{}

func (parser) Parse(line string) (core.LogEvent, bool) {
	if m := dhcpRe.FindStringSubmatch(line); m != nil {
		mac, err := core.NormalizeMAC(m[2])
		if err != nil {
			return core.LogEvent{}, false
		}
		return core.LogEvent{Action: "dhcp-ack", SrcIP: m[1], SrcMAC: mac, Raw: line}, true
	}

	f := kv.Parse(line)
	src := core.NormalizeIP(f["src"])
	if src == "" {
		return core.LogEvent{}, false
	}
	ev := core.LogEvent{
		SrcIP:   src,
		SrcMAC:  sourceMAC(f),
		SrcPort: atoi(f["spt"]),
		DstIP:   core.NormalizeIP(f["dst"]),
		DstPort: atoi(f["dpt"]),
		Proto:   strings.ToUpper(f["proto"]),
		Raw:     line,
	}
	if m := ruleRe.FindStringSubmatch(line); m != nil {
		ev.Rule, ev.Action = m[1], ruleActions[m[2]]
	} else if act := f["act"]; act != "" {
		ev.Action = strings.ToLower(act)
	}
	return ev, true
}

func sourceMAC(f map[string]string) string {
	for _, k := range []string{"smac", "unificlientmac"} {
		if mac, err := core.NormalizeMAC(f[k]); err == nil {
			return mac
		}
	}
	// iptables: MAC=<destino: 6 bytes>:<origem: 6 bytes>:<ethertype: 2 bytes>
	if parts := strings.Split(f["mac"], ":"); len(parts) >= 12 {
		if mac, err := core.NormalizeMAC(strings.Join(parts[6:12], ":")); err == nil {
			return mac
		}
	}
	return ""
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
