package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/auth"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/files"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/proto"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/wire"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/xfer"
)

// finishedTTL é por quanto tempo o servidor ainda responde a FIN repetido
// de um upload já concluído.
const finishedTTL = 10 * time.Second

// session é o estado de um cliente. Protegido por Server.mu.
type session struct {
	id       uint64
	addr     string // endereço do cliente; datagramas de outro endereço são ignorados
	nonce    []byte // desafio enviado no CHALLENGE
	authed   bool
	lastSeen time.Time
	active   int // transferências em andamento

	// Idempotência: a última requisição atendida e a resposta enviada.
	// Requisição repetida (mesmo Seq) recebe a mesma resposta, sem reexecutar.
	hasLast  bool
	lastSeq  uint32
	lastResp []byte
}

// handleHello inicia uma sessão: gera Session ID e desafio e responde
// CHALLENGE. HELLO repetido cria outra sessão; a sobra expira sozinha.
func (s *Server) handleHello(h wire.Header, addr net.Addr) {
	s.mu.Lock()
	if len(s.sessions) >= s.cfg.MaxSessions {
		s.mu.Unlock()
		s.reply(addr, wire.Header{Type: wire.TypeError, Ack: h.Seq},
			proto.ErrorPayload(proto.CodeBusy, "limite de sessões atingido"))
		return
	}
	sess := &session{id: auth.NewID(), addr: addr.String(), nonce: auth.NewNonce(), lastSeen: time.Now()}
	s.sessions[sess.id] = sess
	s.mu.Unlock()

	payload, _ := proto.Marshal(proto.Challenge{Nonce: hex.EncodeToString(sess.nonce)})
	s.reply(addr, wire.Header{Type: wire.TypeChallenge, SessionID: sess.id, Ack: h.Seq}, payload)
	s.log.Debug("HELLO", "de", addr, "sessão", fmt.Sprintf("%016x", sess.id))
}

// handleRequest trata AUTH, LIST, GET e PUT de uma sessão existente.
func (s *Server) handleRequest(ctx context.Context, h wire.Header, p []byte, addr net.Addr) {
	errReply := func(code, msg string) {
		s.reply(addr, wire.Header{Type: wire.TypeError, SessionID: h.SessionID, Ack: h.Seq}, proto.ErrorPayload(code, msg))
	}

	s.mu.Lock()
	sess := s.sessions[h.SessionID]
	if sess == nil || sess.addr != addr.String() {
		s.mu.Unlock()
		errReply(proto.CodeNotAuthenticated, "sessão inexistente ou expirada; autentique-se de novo")
		return
	}
	sess.lastSeen = time.Now()
	if sess.hasLast && h.Seq == sess.lastSeq {
		resp := sess.lastResp // requisição retransmitida: mesma resposta
		s.mu.Unlock()
		s.conn.WriteTo(resp, addr)
		return
	}
	if sess.hasLast && h.Seq < sess.lastSeq {
		s.mu.Unlock()
		return // requisição antiga atrasada
	}
	if h.Type != wire.TypeAuth && !sess.authed {
		s.mu.Unlock()
		errReply(proto.CodeNotAuthenticated, "sessão não autenticada")
		return
	}
	s.mu.Unlock()

	var rh wire.Header
	var rp []byte
	var start func() // GET/PUT: inicia a transferência depois da resposta
	switch h.Type {
	case wire.TypeAuth:
		rh, rp = s.doAuth(sess, p)
	case wire.TypeList:
		rh, rp = s.doList(p)
	case wire.TypeGet:
		rh, rp, start = s.doGet(ctx, sess, p, addr)
	case wire.TypePut:
		rh, rp, start = s.doPut(ctx, sess, p, addr)
	}
	rh.SessionID, rh.Ack = sess.id, h.Seq
	resp := s.reply(addr, rh, rp)

	s.mu.Lock()
	sess.hasLast, sess.lastSeq, sess.lastResp = true, h.Seq, resp
	s.mu.Unlock()

	if start != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			start()
		}()
	}
}

func errorResp(code, msg string) (wire.Header, []byte) {
	return wire.Header{Type: wire.TypeError}, proto.ErrorPayload(code, msg)
}

func errorFrom(err error) (wire.Header, []byte) {
	return errorResp(proto.CodeFor(err), err.Error())
}

// doAuth confere a resposta ao desafio.
func (s *Server) doAuth(sess *session, p []byte) (wire.Header, []byte) {
	var a proto.Auth
	if err := proto.Unmarshal(p, &a); err != nil {
		return errorFrom(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.authed {
		return wire.Header{Type: wire.TypeAuthOK}, nil
	}
	if sess.nonce == nil || !auth.Verify(s.key, sess.id, sess.nonce, a.MAC) {
		// Desafio de uso único: depois de uma falha a sessão não serve mais.
		sess.nonce = nil
		s.log.Warn("autenticação recusada", "de", sess.addr)
		return errorResp(proto.CodeAuthFailed, "senha incorreta")
	}
	sess.authed, sess.nonce = true, nil
	s.log.Info("cliente autenticado", "de", sess.addr, "sessão", fmt.Sprintf("%016x", sess.id))
	return wire.Header{Type: wire.TypeAuthOK}, nil
}

// doList devolve uma página da listagem que caiba em um datagrama.
func (s *Server) doList(p []byte) (wire.Header, []byte) {
	var req proto.ListReq
	if err := proto.Unmarshal(p, &req); err != nil {
		return errorFrom(err)
	}
	entries, err := s.cfg.Catalog.List()
	if err != nil {
		return errorFrom(err)
	}
	if req.Offset < 0 || req.Offset > len(entries) {
		return errorResp(proto.CodeBadRequest, fmt.Sprintf("offset %d fora da lista", req.Offset))
	}
	payload, err := ListPage(entries, req.Offset)
	if err != nil {
		return errorFrom(err)
	}
	return wire.Header{Type: wire.TypeListResult}, payload
}

// ListPage monta o LIST_RESULT com o maior número de entradas, a partir de
// offset, que caiba no payload de um datagrama.
func ListPage(entries []files.Entry, offset int) ([]byte, error) {
	res := proto.ListResult{Files: []files.Entry{}, Next: -1}
	best, err := proto.Marshal(res)
	if err != nil {
		return nil, err
	}
	for i := offset; i < len(entries); i++ {
		res.Files = append(res.Files, entries[i])
		res.Next = i + 1
		if i+1 == len(entries) {
			res.Next = -1
		}
		b, err := proto.Marshal(res)
		if err != nil { // não coube: devolve a página anterior
			break
		}
		best = b
	}
	return best, nil
}

// beginTransfer reserva uma transferência e cria sua vconn. Retorna nil se o
// limite de transferências simultâneas foi atingido.
func (s *Server) beginTransfer(sess *session, addr net.Addr) (xfer.IDs, *vconn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.transfers) >= s.cfg.MaxTransfers {
		return xfer.IDs{}, nil
	}
	ids := xfer.IDs{Session: sess.id, Transfer: auth.NewID()}
	vc := newVConn(s.conn, addr)
	s.transfers[xferKey{ids.Session, ids.Transfer}] = &transfer{vc: vc, addr: addr.String()}
	sess.active++
	return ids, vc
}

// endTransfer remove a transferência; finalReply (se houver) passa a
// responder FIN repetido por finishedTTL.
func (s *Server) endTransfer(sess *session, ids xfer.IDs, vc *vconn, finalReply []byte) {
	vc.Close()
	key := xferKey{ids.Session, ids.Transfer}
	s.mu.Lock()
	delete(s.transfers, key)
	if finalReply != nil {
		s.finished[key] = finished{reply: finalReply, expires: time.Now().Add(finishedTTL)}
	}
	sess.active--
	sess.lastSeen = time.Now()
	s.mu.Unlock()
}

// doGet responde META e inicia o envio do arquivo em outra goroutine.
func (s *Server) doGet(ctx context.Context, sess *session, p []byte, addr net.Addr) (wire.Header, []byte, func()) {
	var req proto.GetReq
	if err := proto.Unmarshal(p, &req); err != nil {
		return fail(errorFrom(err))
	}
	f, size, err := s.cfg.Catalog.Open(req.Name)
	if err != nil {
		return fail(errorFrom(err))
	}
	sum, err := s.cfg.Catalog.Hash(req.Name)
	if err != nil {
		f.Close()
		return fail(errorFrom(err))
	}
	meta := files.NewMeta(req.Name, size, sum)
	payload, err := meta.Marshal()
	if err != nil {
		f.Close()
		return fail(errorFrom(err))
	}
	ids, vc := s.beginTransfer(sess, addr)
	if vc == nil {
		f.Close()
		return fail(errorResp(proto.CodeBusy, "limite de transferências simultâneas atingido"))
	}

	// start roda numa goroutine própria depois que handleRequest enviou o
	// META, para que o primeiro DATA não chegue antes do META.
	start := func() {
		defer f.Close()
		log := s.log.With("op", "GET", "arquivo", meta.Name, "cliente", addr.String(),
			"transfer", fmt.Sprintf("%016x", ids.Transfer))
		log.Info("início do envio", "bytes", size, "sha256_original", hex.EncodeToString(sum[:]))
		st, err := xfer.Send(ctx, vc, addr, ids, f, size, s.cfg.Xfer)
		s.endTransfer(sess, ids, vc, nil)
		if err != nil {
			log.Error("envio falhou", "erro", err, "retransmissões", st.Retransmissions)
			return
		}
		log.Info("envio concluído", statsAttrs(st)...)
	}
	return wire.Header{Type: wire.TypeMeta, TransferID: ids.Transfer}, payload, start
}

// doPut valida o META do upload, responde META_ACK e inicia o recebimento.
func (s *Server) doPut(ctx context.Context, sess *session, p []byte, addr net.Addr) (wire.Header, []byte, func()) {
	meta, err := files.UnmarshalMeta(p)
	if err != nil {
		return fail(errorFrom(err))
	}
	sink, err := s.cfg.Catalog.NewSink(meta.Name, meta.Size, meta.SHA256)
	if err != nil {
		return fail(errorFrom(err))
	}
	ids, vc := s.beginTransfer(sess, addr)
	if vc == nil {
		sink.Abort()
		return fail(errorResp(proto.CodeBusy, "limite de transferências simultâneas atingido"))
	}

	start := func() {
		log := s.log.With("op", "PUT", "arquivo", meta.Name, "cliente", addr.String(),
			"transfer", fmt.Sprintf("%016x", ids.Transfer))
		log.Info("início do recebimento", "bytes", meta.Size, "sha256_original", hex.EncodeToString(meta.SHA256[:]))
		st, err := xfer.Receive(ctx, vc, addr, ids, sink, meta.Size, s.cfg.Xfer, sink.Commit)

		// Resposta final guardada para FIN repetido depois do fim.
		var final wire.Header
		var payload []byte
		if err == nil {
			final = wire.Header{Type: wire.TypeFinAck, Ack: meta.Blocks()}
		} else {
			final = wire.Header{Type: wire.TypeError, Ack: meta.Blocks()}
			payload = proto.ErrorPayload(proto.CodeFor(err), err.Error())
			sink.Abort()
		}
		final.SessionID, final.TransferID = ids.Session, ids.Transfer
		buf := make([]byte, wire.MaxDatagram)
		n, _ := wire.Encode(buf, final, payload)
		s.endTransfer(sess, ids, vc, buf[:n])

		got := sink.Received()
		if err != nil {
			log.Error("recebimento falhou", "erro", err, "sha256_recebido", hex.EncodeToString(got[:]))
			return
		}
		log.Info("recebimento concluído", append(statsAttrs(st), "sha256_recebido", hex.EncodeToString(got[:]))...)
	}
	return wire.Header{Type: wire.TypeMetaAck, TransferID: ids.Transfer, Window: uint32(max(1, s.cfg.Xfer.Window))}, nil, start
}

// fail adapta uma resposta de erro ao retorno de doGet/doPut (sem transferência).
func fail(h wire.Header, p []byte) (wire.Header, []byte, func()) { return h, p, nil }

func statsAttrs(st xfer.Stats) []any {
	return []any{"bytes", st.Bytes, "duração", st.Duration.Round(time.Millisecond),
		"blocos", st.Blocks, "data_enviados", st.DataSent, "retransmissões", st.Retransmissions,
		"duplicatas", st.Duplicates, "corrompidos", st.Corrupt}
}
