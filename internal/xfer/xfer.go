// Package xfer é a fronteira entre a aplicação (cliente/servidor) e o
// transporte confiável.
//
// ATENÇÃO: a implementação deste pacote é um STUB stop-and-wait, provisório,
// que existe só para a aplicação poder ser desenvolvida e testada antes do
// transporte Selective Repeat (internal/transport, Pedro) ficar pronto. A
// assinatura de Send e Receive é o contrato descrito em docs/integracao.md;
// quando o transporte real existir, Send e Receive passam a apenas chamá-lo
// (ou cliente e servidor chamam internal/transport diretamente).
//
// Fase coberta: DATA/ACK e FIN/FIN_ACK de uma transferência já negociada.
// META e a escolha do Transfer ID são feitos antes, pela aplicação.
package xfer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/files"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/proto"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/transport"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/wire"
)

// IDs identifica a transferência nos campos Session ID e Transfer ID.
type IDs struct {
	Session  uint64
	Transfer uint64
}

// Config parametriza a transferência.
type Config struct {
	Window     int           // janela em blocos (ignorada pelo stub: sempre 1)
	RTO        time.Duration // timeout de retransmissão (fixo no stub)
	MaxRetries int           // retransmissões do mesmo bloco antes de desistir
	Idle       time.Duration // tempo máximo sem nenhum datagrama válido do par
	Linger     time.Duration // receptor: tempo respondendo FIN repetido após o FIN_ACK
}

// DefaultConfig são os valores usados quando um campo é zero.
var DefaultConfig = Config{Window: 32, RTO: 300 * time.Millisecond, MaxRetries: 10,
	Idle: 30 * time.Second, Linger: time.Second}

func (c Config) withDefaults() Config {
	d := DefaultConfig
	if c.Window <= 0 {
		c.Window = d.Window
	}
	if c.RTO <= 0 {
		c.RTO = d.RTO
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = d.MaxRetries
	}
	if c.Idle <= 0 {
		c.Idle = d.Idle
	}
	if c.Linger < 0 {
		c.Linger = 0
	} else if c.Linger == 0 {
		c.Linger = d.Linger
	}
	return c
}

// Stats resume uma transferência (seção 5 do enunciado).
type Stats struct {
	Blocks          uint32        // blocos do arquivo
	Bytes           int64         // bytes úteis do arquivo
	DataSent        uint64        // DATA enviados, incluindo retransmissões (emissor)
	Retransmissions uint64        // DATA reenviados (emissor)
	AcksReceived    uint64        // ACKs válidos recebidos (emissor)
	DataReceived    uint64        // DATA válidos recebidos (receptor)
	Duplicates      uint64        // DATA repetidos recebidos (receptor)
	Corrupt         uint64        // datagramas rejeitados por wire.Decode
	Duration        time.Duration // do primeiro DATA ao FIN_ACK
}

// ErrTimeout indica que o par parou de responder.
var ErrTimeout = errors.New("xfer: par não responde")

// Send envia size bytes de src como a transferência ids para peer. Retorna
// quando o receptor confirma o FIN (FIN_ACK), quando o receptor envia ERROR
// (*proto.RemoteError, por exemplo HASH_MISMATCH) ou em timeout.
func Send(ctx context.Context, conn transport.PacketConn, peer net.Addr, ids IDs,
	src io.ReaderAt, size int64, cfg Config) (Stats, error) {

	cfg = cfg.withDefaults()
	st := Stats{Blocks: files.NumBlocks(size), Bytes: size}
	start := time.Now()
	defer conn.SetReadDeadline(time.Time{})

	block := make([]byte, files.BlockSize)
	out := make([]byte, wire.MaxDatagram)
	in := make([]byte, 64*1024)

	// exchange envia (h, payload) e espera uma resposta do tipo want com
	// Ack == ack, retransmitindo por timeout.
	exchange := func(h wire.Header, payload []byte, want wire.MsgType, ack uint32, isData bool) error {
		n, err := wire.Encode(out, h, payload)
		if err != nil {
			return err
		}
		for try := 0; try <= cfg.MaxRetries; try++ {
			if try > 0 && isData {
				st.Retransmissions++
			}
			if isData {
				st.DataSent++
			}
			if _, err := conn.WriteTo(out[:n], peer); err != nil {
				return err
			}
			got, err := waitFor(ctx, conn, in, ids, time.Now().Add(cfg.RTO), &st,
				func(rh wire.Header) bool { return rh.Type == want && rh.Ack == ack })
			if err != nil {
				return err
			}
			if got {
				return nil
			}
		}
		return fmt.Errorf("%w: %v %d sem confirmação após %d retransmissões", ErrTimeout, h.Type, ack, cfg.MaxRetries)
	}

	for seq := range st.Blocks {
		off, k := files.BlockRange(seq, size)
		if _, err := src.ReadAt(block[:k], off); err != nil && !(errors.Is(err, io.EOF) && k > 0) {
			return st, fmt.Errorf("lendo bloco %d: %w", seq, err)
		}
		h := wire.Header{Type: wire.TypeData, SessionID: ids.Session, TransferID: ids.Transfer, Seq: seq}
		if err := exchange(h, block[:k], wire.TypeAck, seq, true); err != nil {
			return st, err
		}
		st.AcksReceived++
	}
	fin := wire.Header{Type: wire.TypeFin, SessionID: ids.Session, TransferID: ids.Transfer, Seq: st.Blocks}
	err := exchange(fin, nil, wire.TypeFinAck, st.Blocks, false)
	st.Duration = time.Since(start)
	return st, err
}

// Receive recebe a transferência ids de peer e escreve os size bytes em dst,
// em ordem. Ao receber o FIN com todos os blocos gravados, chama finalize
// (tipicamente files.Sink.Commit, que confere o SHA-256): se finalize
// falhar, envia ERROR com o código correspondente (proto.CodeFor) e retorna
// o erro; senão envia FIN_ACK.
//
// Se Receive retornar erro, quem chamou deve descartar dst (Sink.Abort).
func Receive(ctx context.Context, conn transport.PacketConn, peer net.Addr, ids IDs,
	dst io.Writer, size int64, cfg Config, finalize func() error) (Stats, error) {

	cfg = cfg.withDefaults()
	st := Stats{Blocks: files.NumBlocks(size), Bytes: size}
	defer conn.SetReadDeadline(time.Time{})

	in := make([]byte, 64*1024)
	out := make([]byte, wire.MaxDatagram)
	reply := func(h wire.Header, payload []byte) {
		h.SessionID, h.TransferID = ids.Session, ids.Transfer
		if n, err := wire.Encode(out, h, payload); err == nil {
			conn.WriteTo(out[:n], peer)
		}
	}

	var start time.Time
	var expected uint32 // próximo bloco a gravar
	for {
		h, p, err := readOwn(ctx, conn, in, ids, time.Now().Add(cfg.Idle), &st)
		if err != nil {
			return st, err
		}
		switch h.Type {
		case wire.TypeData:
			if start.IsZero() {
				start = time.Now()
			}
			switch {
			case h.Seq < expected: // duplicata: o ACK anterior pode ter se perdido
				st.Duplicates++
				reply(wire.Header{Type: wire.TypeAck, Ack: h.Seq, Window: 1}, nil)
			case h.Seq == expected:
				if _, k := files.BlockRange(h.Seq, size); k != len(p) {
					continue // tamanho incoerente com o META: descarta
				}
				if _, err := dst.Write(p); err != nil {
					reply(wire.Header{Type: wire.TypeError}, proto.ErrorPayload(proto.CodeFor(err), err.Error()))
					return st, err
				}
				st.DataReceived++
				expected++
				reply(wire.Header{Type: wire.TypeAck, Ack: h.Seq, Window: 1}, nil)
			}
			// h.Seq > expected: fora da janela (1) no stub; descarta.
		case wire.TypeFin:
			if h.Seq != st.Blocks || expected != st.Blocks {
				continue
			}
			if start.IsZero() {
				start = time.Now()
			}
			if err := finalize(); err != nil {
				reply(wire.Header{Type: wire.TypeError, Ack: h.Seq}, proto.ErrorPayload(proto.CodeFor(err), err.Error()))
				st.Duration = time.Since(start)
				return st, err
			}
			reply(wire.Header{Type: wire.TypeFinAck, Ack: st.Blocks}, nil)
			st.Duration = time.Since(start)
			linger(ctx, conn, in, ids, cfg.Linger, &st, func() {
				reply(wire.Header{Type: wire.TypeFinAck, Ack: st.Blocks}, nil)
			})
			return st, nil
		case wire.TypeError:
			return st, proto.ParseError(p)
		}
	}
}

// linger responde FINs repetidos (FIN_ACK perdido) por d.
func linger(ctx context.Context, conn transport.PacketConn, buf []byte, ids IDs, d time.Duration, st *Stats, onFin func()) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		h, _, err := readOwn(ctx, conn, buf, ids, deadline, st)
		if err != nil {
			return
		}
		if h.Type == wire.TypeFin {
			onFin()
		}
	}
}

// waitFor lê até match aceitar um datagrama da transferência (true), até o
// prazo (false) ou até um ERROR do par (erro).
func waitFor(ctx context.Context, conn transport.PacketConn, buf []byte, ids IDs,
	deadline time.Time, st *Stats, match func(wire.Header) bool) (bool, error) {
	for {
		h, p, err := readOwn(ctx, conn, buf, ids, deadline, st)
		if errors.Is(err, ErrTimeout) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if h.Type == wire.TypeError {
			return false, proto.ParseError(p)
		}
		if match(h) {
			return true, nil
		}
	}
}

// readOwn devolve o próximo datagrama válido desta transferência. Datagramas
// corrompidos são contados; os de outras transferências, ignorados. Retorna
// ErrTimeout se nada chegar até deadline.
func readOwn(ctx context.Context, conn transport.PacketConn, buf []byte, ids IDs,
	deadline time.Time, st *Stats) (wire.Header, []byte, error) {
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetReadDeadline(deadline)
	for {
		if err := ctx.Err(); err != nil {
			return wire.Header{}, nil, err
		}
		n, _, err := conn.ReadFrom(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if err := ctx.Err(); err != nil {
				return wire.Header{}, nil, err
			}
			return wire.Header{}, nil, ErrTimeout
		}
		if err != nil {
			return wire.Header{}, nil, err
		}
		h, p, err := wire.Decode(buf[:n])
		if err != nil {
			st.Corrupt++
			continue
		}
		if h.SessionID != ids.Session || h.TransferID != ids.Transfer {
			continue
		}
		return h, p, nil
	}
}
