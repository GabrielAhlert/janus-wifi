// Package kv extrai pares chave=valor de linhas de log. Serve ao formato do
// iptables (SRC=1.2.3.4 DPT=443), ao CEF (src=1.2.3.4 dpt=443) e ao Sophos
// (src_ip="1.2.3.4"), então é compartilhado pelos parsers.
package kv

import "strings"

// Parse devolve as chaves em minúsculas. Valores podem estar entre aspas;
// sem aspas, terminam em espaço, tab ou "|". Chaves repetidas mantêm o
// primeiro valor.
func Parse(line string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(line) {
		eq := strings.IndexByte(line[i:], '=')
		if eq < 0 {
			break
		}
		eq += i
		start := eq
		for start > i && isKeyChar(line[start-1]) {
			start--
		}
		key := strings.ToLower(line[start:eq])

		j := eq + 1
		var val string
		if j < len(line) && line[j] == '"' {
			end := strings.IndexByte(line[j+1:], '"')
			if end < 0 {
				val, j = line[j+1:], len(line)
			} else {
				val, j = line[j+1:j+1+end], j+2+end
			}
		} else {
			end := strings.IndexAny(line[j:], " \t|")
			if end < 0 {
				val, j = line[j:], len(line)
			} else {
				val, j = line[j:j+end], j+end
			}
		}
		if _, dup := out[key]; key != "" && !dup {
			out[key] = val
		}
		i = j
	}
	return out
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}
