package main

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// Use the ordinary net resolver for the frozen domain's TXT. Production still
// parses the DNS record and verifies the full chain/status evidence.
func serveRosterTXT(t *testing.T, record string) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = old; conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			if n < 16 {
				continue
			}
			end := 12
			var labels []string
			for end < n && packet[end] != 0 {
				size := int(packet[end])
				end++
				if end+size >= n {
					break
				}
				labels = append(labels, string(packet[end:end+size]))
				end += size
			}
			if end+5 > n {
				continue
			}
			end++
			typ := binary.BigEndian.Uint16(packet[end : end+2])
			end += 4
			answer := append([]byte(nil), packet[:end]...)
			answer[2], answer[3] = 0x81, 0x80
			binary.BigEndian.PutUint16(answer[6:8], 0)
			binary.BigEndian.PutUint16(answer[8:10], 0)
			binary.BigEndian.PutUint16(answer[10:12], 0)

			if typ == 16 && strings.Join(labels, ".") == "_awid.example.com" {
				binary.BigEndian.PutUint16(answer[6:8], 1)
				data := append([]byte{byte(len(record))}, []byte(record)...)
				answer = append(answer, 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, byte(len(data)>>8), byte(len(data)))
				answer = append(answer, data...)
			} else if typ == 1 && (strings.Join(labels, ".") == "registry.example" || strings.Join(labels, ".") == "registry.test") {
				binary.BigEndian.PutUint16(answer[6:8], 1)
				answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
			}
			conn.WriteTo(answer, addr)
		}
	}()
}
