// Package server implementa o servidor Sigma: autenticação, LIST, GET (o
// servidor envia), PUT (o servidor recebe) e PING/PONG para a mini-CDN.
//
// Arquitetura (detalhada em docs/aplicacao.md):
//
//   - Um único socket UDP. Uma goroutine (Serve) lê todos os datagramas,
//     valida com wire.Decode e decide o destino:
//     DATA/ACK/FIN/FIN_ACK/ERROR com Transfer ID → fila da transferência;
//     PING → PONG imediato; HELLO/AUTH/LIST/GET/PUT → handlers de controle.
//   - Handlers de controle rodam na própria goroutine de Serve e são rápidos
//     (nunca esperam a rede). O estado de sessões é protegido por s.mu.
//   - Cada transferência roda em uma goroutine própria com uma conexão
//     virtual (vconn) e chama xfer.Send (GET) ou xfer.Receive (PUT).
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/auth"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/files"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/transport"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/wire"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/xfer"
)

// Config configura o servidor.
type Config struct {
	Catalog  *files.Catalog // diretório de arquivos compartilhados (obrigatório)
	Password string         // senha exigida dos clientes (obrigatória)
	Xfer     xfer.Config    // parâmetros das transferências

	SessionIdle  time.Duration // sessão sem tráfego é removida (padrão 2 min)
	MaxSessions  int           // padrão 64
	MaxTransfers int           // transferências simultâneas (padrão 16)
	Logger       *slog.Logger  // padrão slog.Default()
}

// Server é um servidor Sigma ligado a um socket.
type Server struct {
	cfg  Config
	conn transport.PacketConn
	key  [sha256.Size]byte
	log  *slog.Logger

	mu        sync.Mutex
	sessions  map[uint64]*session
	transfers map[xferKey]*transfer
	finished  map[xferKey]finished

	wg sync.WaitGroup
}

type xferKey struct{ session, transfer uint64 }

// transfer é uma transferência em andamento.
type transfer struct {
	vc   *vconn
	addr string
}

// finished guarda a resposta final de uma transferência recebida (PUT) por
// alguns segundos, para responder a FIN repetido depois que ela terminou.
type finished struct {
	reply   []byte
	expires time.Time
}

// New cria o servidor sobre conn (normalmente um *net.UDPConn).
func New(conn transport.PacketConn, cfg Config) (*Server, error) {
	if cfg.Catalog == nil {
		return nil, errors.New("server: Catalog obrigatório")
	}
	if cfg.Password == "" {
		return nil, errors.New("server: senha obrigatória")
	}
	if cfg.SessionIdle <= 0 {
		cfg.SessionIdle = 2 * time.Minute
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}
	if cfg.MaxTransfers <= 0 {
		cfg.MaxTransfers = 16
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{
		cfg: cfg, conn: conn, key: auth.Key(cfg.Password), log: cfg.Logger,
		sessions:  map[uint64]*session{},
		transfers: map[xferKey]*transfer{},
		finished:  map[xferKey]finished{},
	}, nil
}

// WarmHashes calcula o SHA-256 de todos os arquivos do catálogo, para que o
// primeiro GET não pare o laço principal lendo 80 MB. Registra os hashes no
// log (são o "hash original" do relatório).
func (s *Server) WarmHashes() error {
	entries, err := s.cfg.Catalog.List()
	if err != nil {
		return err
	}
	for _, e := range entries {
		sum, err := s.cfg.Catalog.Hash(e.Name)
		if err != nil {
			return fmt.Errorf("hash de %q: %w", e.Name, err)
		}
		s.log.Info("arquivo disponível", "nome", e.Name, "bytes", e.Size, "sha256", hex.EncodeToString(sum[:]))
	}
	return nil
}

// Serve atende até ctx ser cancelado ou o socket falhar. Ao sair, cancela as
// transferências em andamento e espera que terminem.
func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		s.wg.Wait()
	}()

	buf := make([]byte, 64*1024)
	lastSweep := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		// Prazo curto para checar ctx e limpar sessões periodicamente.
		s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := s.conn.ReadFrom(buf)
		if time.Since(lastSweep) > time.Second {
			s.sweep(time.Now())
			lastSweep = time.Now()
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.handle(ctx, buf[:n], addr)
	}
}

// handle trata um datagrama recebido. dg é reutilizado depois do retorno.
func (s *Server) handle(ctx context.Context, dg []byte, addr net.Addr) {
	h, p, err := wire.Decode(dg)
	if err != nil {
		s.log.Debug("datagrama descartado", "de", addr, "erro", err)
		return
	}
	switch h.Type {
	case wire.TypeData, wire.TypeAck, wire.TypeFin, wire.TypeFinAck, wire.TypeError:
		s.route(h, dg, addr)
	case wire.TypePing:
		s.reply(addr, wire.Header{Type: wire.TypePong, Ack: h.Seq}, p)
	case wire.TypeHello:
		s.handleHello(h, addr)
	case wire.TypeAuth, wire.TypeList, wire.TypeGet, wire.TypePut:
		s.handleRequest(ctx, h, p, addr)
	default:
		// Tipos que só o servidor envia (CHALLENGE, META, ...): ignorados.
	}
}

// route entrega um datagrama de transferência à vconn correspondente.
func (s *Server) route(h wire.Header, dg []byte, addr net.Addr) {
	key := xferKey{h.SessionID, h.TransferID}
	s.mu.Lock()
	t, ok := s.transfers[key]
	fin, done := s.finished[key]
	if sess := s.sessions[h.SessionID]; sess != nil && sess.addr == addr.String() {
		sess.lastSeen = time.Now()
	}
	s.mu.Unlock()

	switch {
	case ok && t.addr == addr.String():
		t.vc.push(append([]byte(nil), dg...))
	case done && h.Type == wire.TypeFin:
		s.conn.WriteTo(fin.reply, addr) // FIN repetido após o fim: reconfirma
	}
}

// reply codifica e envia uma resposta.
func (s *Server) reply(addr net.Addr, h wire.Header, payload []byte) []byte {
	buf := make([]byte, wire.MaxDatagram)
	n, err := wire.Encode(buf, h, payload)
	if err != nil {
		s.log.Error("codificando resposta", "tipo", h.Type, "erro", err)
		return nil
	}
	s.conn.WriteTo(buf[:n], addr)
	return buf[:n]
}

// sweep remove sessões ociosas e respostas finais expiradas.
func (s *Server) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.active == 0 && now.Sub(sess.lastSeen) > s.cfg.SessionIdle {
			delete(s.sessions, id)
			s.log.Debug("sessão expirada", "sessão", fmt.Sprintf("%016x", id))
		}
	}
	for k, f := range s.finished {
		if now.After(f.expires) {
			delete(s.finished, k)
		}
	}
}
