package core

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Tipos de índice cego. Usar o mesmo tipo em tabelas diferentes permite
// cruzar sessões do portal com eventos de firewall sem decifrar nada.
const (
	IndexMAC = "mac"
	IndexIP  = "ip"
)

// FieldIndex é o tipo de índice cego de um campo do formulário.
func FieldIndex(key string) string { return "field:" + key }

var errInvalidCPF = errors.New("CPF inválido")

// NormalizeCPF valida os dígitos verificadores e devolve só os 11 dígitos.
func NormalizeCPF(s string) (string, error) {
	d := onlyDigits(s)
	if len(d) != 11 || strings.Count(d, d[:1]) == 11 {
		return "", errInvalidCPF
	}
	for _, n := range []int{9, 10} {
		sum := 0
		for i := 0; i < n; i++ {
			sum += int(d[i]-'0') * (n + 1 - i)
		}
		if sum*10%11%10 != int(d[n]-'0') {
			return "", errInvalidCPF
		}
	}
	return d, nil
}

// NormalizeMAC aceita aa:bb:cc:dd:ee:ff, AA-BB-..., aabb.ccdd.eeff ou
// aabbccddeeff e devolve o formato canônico aa:bb:cc:dd:ee:ff.
func NormalizeMAC(s string) (string, error) {
	s = strings.TrimSpace(s)
	if hw, err := net.ParseMAC(s); err == nil && len(hw) == 6 {
		return hw.String(), nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 6 {
		return net.HardwareAddr(b).String(), nil
	}
	return "", fmt.Errorf("MAC inválido: %q", s)
}

// NormalizeIP devolve o IP em forma canônica ou "" se for inválido.
func NormalizeIP(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
