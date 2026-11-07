// Package syslog recebe mensagens syslog por UDP e TCP (RFC 5424/3164, com
// framing por quebra de linha ou octet counting da RFC 6587) e as entrega a
// um Handler junto com o IP de quem enviou.
package syslog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Handler func(from netip.Addr, msg string)

type Server struct {
	Addr    string
	Handler Handler
	Log     *slog.Logger
}

const (
	maxMessage  = 64 << 10
	idleTimeout = 5 * time.Minute
)

var errBadFrame = errors.New("syslog: frame inválido")

// Run escuta até ctx ser cancelado.
func (s *Server) Run(ctx context.Context) error {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", s.Addr)
	if err != nil {
		return fmt.Errorf("syslog udp: %w", err)
	}
	ln, err := lc.Listen(ctx, "tcp", s.Addr)
	if err != nil {
		pc.Close()
		return fmt.Errorf("syslog tcp: %w", err)
	}
	s.Log.Info("syslog escutando", "addr", s.Addr)

	stop := context.AfterFunc(ctx, func() {
		pc.Close()
		ln.Close()
	})
	defer stop()

	var wg sync.WaitGroup
	wg.Go(func() { s.serveUDP(pc) })
	wg.Go(func() { s.serveTCP(ctx, ln) })
	wg.Wait()
	return nil
}

func (s *Server) serveUDP(pc net.PacketConn) {
	buf := make([]byte, maxMessage)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if ua, ok := addr.(*net.UDPAddr); ok {
			s.Handler(ua.AddrPort().Addr().Unmap(), Body(string(buf[:n])))
		}
	}
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	ta, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	from := ta.AddrPort().Addr().Unmap()
	r := bufio.NewReaderSize(conn, maxMessage)
	for {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
		msg, err := readFrame(r)
		if msg != "" {
			s.Handler(from, Body(msg))
		}
		if err != nil {
			return
		}
	}
}

// readFrame lê uma mensagem em octet counting ("123 <msg>") ou terminada por "\n".
func readFrame(r *bufio.Reader) (string, error) {
	b, err := r.Peek(1)
	if err != nil {
		return "", err
	}
	if b[0] >= '1' && b[0] <= '9' {
		prefix, err := r.ReadString(' ')
		if err != nil {
			return "", err
		}
		n, err := strconv.Atoi(strings.TrimSpace(prefix))
		if err != nil || n > maxMessage {
			return "", errBadFrame
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	}
	line, err := r.ReadSlice('\n')
	return string(line), err
}

// Body remove o cabeçalho de prioridade (<PRI>) e espaços finais. O resto
// (timestamp, host, tag) fica: os parsers procuram pares chave=valor.
func Body(raw string) string {
	raw = strings.TrimRight(raw, "\r\n\x00 ")
	if strings.HasPrefix(raw, "<") {
		if i := strings.IndexByte(raw, '>'); i > 0 && i <= 4 {
			raw = raw[i+1:]
		}
	}
	return raw
}
