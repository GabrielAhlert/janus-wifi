package core

import (
	"net/netip"
	"time"
)

// ClientInfo identifica o dispositivo do visitante.
type ClientInfo struct {
	MAC       string `json:"mac"`
	APMAC     string `json:"ap_mac,omitempty"`
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// SessionPayload é a parte cifrada de uma sessão.
type SessionPayload struct {
	Client ClientInfo        `json:"client"`
	Fields map[string]string `json:"fields"`
}

// SessionRecord é uma sessão (acesso liberado) como fica no banco: campos
// em texto puro à parte e o restante cifrado em Payload.
type SessionRecord struct {
	ID        int64
	SiteID    int64
	TermsID   int64
	CreatedAt time.Time
	ExpiresAt time.Time
	SSID      string
	Plain     map[string]string
	Payload   []byte
}

// IndexEntry é um índice cego (HMAC) que permite busca por igualdade.
type IndexEntry struct {
	Kind  string
	Value []byte
}

// LogEvent é um evento de firewall/DHCP normalizado, independente do fabricante.
type LogEvent struct {
	SrcIP   string `json:"src_ip"`
	SrcMAC  string `json:"src_mac,omitempty"`
	SrcPort int    `json:"src_port,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`
	Proto   string `json:"proto,omitempty"`
	// NATIP/NATPort: endereço público após NAT, quando o equipamento informa.
	NATIP   string `json:"nat_ip,omitempty"`
	NATPort int    `json:"nat_port,omitempty"`
	Action  string `json:"action,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Raw     string `json:"raw"`
}

// LogRecord é um LogEvent cifrado e encadeado, como fica no banco.
type LogRecord struct {
	ID          int64
	ReceivedAt  time.Time
	SourceID    int64
	SrcIPIndex  []byte
	SrcMACIndex []byte
	Payload     []byte
	PrevHash    []byte
	Hash        []byte
}

// LogSource é um equipamento autorizado a enviar syslog, e o parser usado.
type LogSource struct {
	ID        int64
	Name      string
	SenderIP  netip.Addr
	Parser    string
	Enabled   bool
	CreatedAt time.Time
}

type Admin struct {
	ID        int64
	Email     string
	CreatedAt time.Time
}
