// Package control implementa a troca confiável de mensagens de controle do
// Sigma Protocol: o lado que pede (cliente) envia uma requisição e espera a
// resposta correspondente, retransmitindo a requisição por timeout.
//
// Correspondência requisição/resposta: a requisição leva um número em
// Header.Seq; a resposta ecoa esse número em Header.Ack. O servidor guarda a
// última resposta de cada sessão e a reenvia quando recebe a mesma
// requisição de novo, então retransmitir é sempre seguro (idempotente).
package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"time"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/proto"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/transport"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/wire"
)

// Config controla a retransmissão de requisições.
type Config struct {
	// Timeout é a espera pela primeira resposta; dobra a cada tentativa até
	// MaxTimeout (backoff exponencial).
	Timeout    time.Duration
	MaxTimeout time.Duration
	// Attempts é o número total de envios da requisição.
	Attempts int
}

// DefaultConfig cobre RTTs de até ~1 s (cenário 4 tem 400 ms) e desiste em
// cerca de 15 s.
var DefaultConfig = Config{Timeout: 500 * time.Millisecond, MaxTimeout: 4 * time.Second, Attempts: 6}

func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = DefaultConfig.Timeout
	}
	if c.MaxTimeout < c.Timeout {
		c.MaxTimeout = max(DefaultConfig.MaxTimeout, c.Timeout)
	}
	if c.Attempts <= 0 {
		c.Attempts = DefaultConfig.Attempts
	}
	return c
}

// ErrNoResponse indica que o par não respondeu após todas as tentativas.
var ErrNoResponse = errors.New("servidor não responde")

// Send codifica e envia um datagrama.
func Send(conn transport.PacketConn, peer net.Addr, h wire.Header, payload []byte) error {
	buf := make([]byte, wire.MaxDatagram)
	n, err := wire.Encode(buf, h, payload)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(buf[:n], peer)
	return err
}

// Call envia a requisição (h, payload) e espera uma resposta de um dos tipos
// em want, ou ERROR, com Ack igual a h.Seq. Se h.SessionID não for zero, a
// resposta precisa ser da mesma sessão. Datagramas que não correspondem são
// descartados.
//
// Um ERROR recebido vira *proto.RemoteError. O payload retornado é uma cópia
// e pode ser guardado.
func Call(ctx context.Context, conn transport.PacketConn, peer net.Addr, h wire.Header,
	payload []byte, cfg Config, want ...wire.MsgType) (wire.Header, []byte, error) {

	cfg = cfg.withDefaults()
	out := make([]byte, wire.MaxDatagram)
	n, err := wire.Encode(out, h, payload)
	if err != nil {
		return wire.Header{}, nil, err
	}
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 64*1024)
	timeout := cfg.Timeout
	for attempt := 1; attempt <= cfg.Attempts; attempt++ {
		if _, err := conn.WriteTo(out[:n], peer); err != nil {
			return wire.Header{}, nil, fmt.Errorf("enviando %v: %w", h.Type, err)
		}
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		conn.SetReadDeadline(deadline)
		for {
			if err := ctx.Err(); err != nil {
				return wire.Header{}, nil, err
			}
			m, addr, err := conn.ReadFrom(buf)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break // próxima tentativa
			}
			if err != nil {
				return wire.Header{}, nil, err
			}
			if peer != nil && addr != nil && addr.String() != peer.String() {
				continue
			}
			rh, rp, err := wire.Decode(buf[:m])
			if err != nil || rh.Ack != h.Seq {
				continue
			}
			if h.SessionID != 0 && rh.SessionID != h.SessionID {
				continue
			}
			if rh.Type == wire.TypeError {
				return rh, nil, proto.ParseError(rp)
			}
			if slices.Contains(want, rh.Type) {
				return rh, slices.Clone(rp), nil
			}
		}
		if err := ctx.Err(); err != nil {
			return wire.Header{}, nil, err
		}
		timeout = min(2*timeout, cfg.MaxTimeout)
	}
	return wire.Header{}, nil, fmt.Errorf("%w: %v sem resposta após %d tentativas", ErrNoResponse, h.Type, cfg.Attempts)
}
