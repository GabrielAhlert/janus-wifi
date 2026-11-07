package ucg

import (
	"testing"

	"janus/internal/core"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		line string
		want core.LogEvent
		ok   bool
	}{
		{
			name: "iptables",
			line: `Nov  6 10:15:02 UCG-Ultra kernel: [GUEST_IN-A-2000] IN=br20 OUT=eth4 MAC=74:ac:b9:12:34:56:aa:bb:cc:dd:ee:ff:08:00 SRC=192.168.20.15 DST=142.250.79.46 LEN=60 TOS=0x00 PROTO=TCP SPT=51544 DPT=443 WINDOW=64240`,
			want: core.LogEvent{SrcIP: "192.168.20.15", SrcMAC: "aa:bb:cc:dd:ee:ff", SrcPort: 51544, DstIP: "142.250.79.46", DstPort: 443, Proto: "TCP", Rule: "GUEST_IN-A-2000", Action: "accept"},
			ok:   true,
		},
		{
			name: "cef",
			line: `CEF:0|Ubiquiti|UniFi Network|9.0.114|201|Firewall|3|src=192.168.20.16 spt=40000 dst=1.1.1.1 dpt=53 proto=udp act=allow smac=AA:BB:CC:00:11:22`,
			want: core.LogEvent{SrcIP: "192.168.20.16", SrcMAC: "aa:bb:cc:00:11:22", SrcPort: 40000, DstIP: "1.1.1.1", DstPort: 53, Proto: "UDP", Action: "allow"},
			ok:   true,
		},
		{
			name: "dhcp",
			line: `Nov  6 10:14:58 UCG-Ultra dnsmasq-dhcp[1234]: DHCPACK(br20) 192.168.20.15 aa:bb:cc:dd:ee:ff iPhone`,
			want: core.LogEvent{SrcIP: "192.168.20.15", SrcMAC: "aa:bb:cc:dd:ee:ff", Action: "dhcp-ack"},
			ok:   true,
		},
		{
			name: "irrelevante",
			line: `Nov  6 10:14:58 UCG-Ultra systemd[1]: Started Daily apt download activities.`,
			ok:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parser{}.Parse(tt.line)
			if ok != tt.ok {
				t.Fatalf("ok = %v, esperado %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			got.Raw = ""
			if got != tt.want {
				t.Fatalf("\nrecebido %+v\nesperado %+v", got, tt.want)
			}
		})
	}
}
