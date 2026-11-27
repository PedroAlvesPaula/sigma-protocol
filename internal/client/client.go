// Package client implementa o lado cliente do Sigma Protocol: autenticação,
// listagem, download (GET) e upload (PUT) com validação SHA-256.
//
// Um Client conversa com um único servidor e faz uma operação por vez. A
// escolha do servidor (mini-CDN) é feita antes, por internal/discovery.
package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/auth"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/control"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/files"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/proto"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/transport"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/wire"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/xfer"
)

// Config configura o cliente.
type Config struct {
	Password string
	Control  control.Config // retransmissão das requisições
	Xfer     xfer.Config    // parâmetros da transferência
}

// Client é uma sessão com um servidor.
type Client struct {
	conn    transport.PacketConn
	server  net.Addr
	cfg     Config
	session uint64
	seq     uint32 // número da última requisição
}

// New cria um cliente que fala com server através de conn (normalmente um
// *net.UDPConn aberto com net.ListenUDP). Chame Login antes das operações.
func New(conn transport.PacketConn, server net.Addr, cfg Config) *Client {
	return &Client{conn: conn, server: server, cfg: cfg}
}

// Server retorna o endereço do servidor.
func (c *Client) Server() net.Addr { return c.server }

// call envia uma requisição da sessão com o próximo número de sequência.
func (c *Client) call(ctx context.Context, typ wire.MsgType, payload []byte, want ...wire.MsgType) (wire.Header, []byte, error) {
	c.seq++
	h := wire.Header{Type: typ, SessionID: c.session, Seq: c.seq}
	return control.Call(ctx, c.conn, c.server, h, payload, c.cfg.Control, want...)
}

// Login faz HELLO → CHALLENGE → AUTH → AUTH_OK. Senha errada retorna um
// *proto.RemoteError com código AUTH_FAILED.
func (c *Client) Login(ctx context.Context) error {
	c.session = 0
	h, p, err := c.call(ctx, wire.TypeHello, nil, wire.TypeChallenge)
	if err != nil {
		return fmt.Errorf("HELLO: %w", err)
	}
	var ch proto.Challenge
	if err := proto.Unmarshal(p, &ch); err != nil {
		return fmt.Errorf("CHALLENGE: %w", err)
	}
	nonce, err := hex.DecodeString(ch.Nonce)
	if err != nil || len(nonce) != auth.NonceLen || h.SessionID == 0 {
		return fmt.Errorf("CHALLENGE inválido")
	}
	c.session = h.SessionID

	mac := auth.MAC(auth.Key(c.cfg.Password), c.session, nonce)
	payload, _ := proto.Marshal(proto.Auth{MAC: hex.EncodeToString(mac)})
	if _, _, err := c.call(ctx, wire.TypeAuth, payload, wire.TypeAuthOK); err != nil {
		return fmt.Errorf("AUTH: %w", err)
	}
	return nil
}

// List busca todas as páginas da listagem de arquivos.
func (c *Client) List(ctx context.Context) ([]files.Entry, error) {
	var all []files.Entry
	offset := 0
	for {
		payload, _ := proto.Marshal(proto.ListReq{Offset: offset})
		_, p, err := c.call(ctx, wire.TypeList, payload, wire.TypeListResult)
		if err != nil {
			return nil, fmt.Errorf("LIST: %w", err)
		}
		var res proto.ListResult
		if err := proto.Unmarshal(p, &res); err != nil {
			return nil, fmt.Errorf("LIST_RESULT: %w", err)
		}
		all = append(all, res.Files...)
		if res.Next < 0 {
			return all, nil
		}
		if res.Next <= offset {
			return nil, fmt.Errorf("LIST_RESULT: paginação não avança (%d)", res.Next)
		}
		offset = res.Next
	}
}

// Result descreve uma transferência concluída (ou que falhou na validação).
type Result struct {
	Meta     files.Meta        // nome, tamanho e SHA-256 original
	Received [sha256.Size]byte // SHA-256 calculado sobre os bytes recebidos/confirmados
	Stats    xfer.Stats
	Elapsed  time.Duration // da requisição ao FIN_ACK, incluindo negociação e validação
}

// Get baixa name para o diretório de dst. O arquivo só aparece em dst se o
// SHA-256 recebido for igual ao original; senão o erro é um
// *files.HashMismatchError com os dois valores.
func (c *Client) Get(ctx context.Context, name string, dst *files.Catalog) (Result, error) {
	var res Result
	start := time.Now()
	payload, err := proto.Marshal(proto.GetReq{Name: name})
	if err != nil {
		return res, err
	}
	h, p, err := c.call(ctx, wire.TypeGet, payload, wire.TypeMeta)
	if err != nil {
		return res, fmt.Errorf("GET %s: %w", name, err)
	}
	meta, err := files.UnmarshalMeta(p)
	if err != nil {
		return res, err
	}
	if meta.Name != name {
		return res, fmt.Errorf("META de %q em resposta a GET %q", meta.Name, name)
	}
	res.Meta = meta

	sink, err := dst.NewSink(meta.Name, meta.Size, meta.SHA256)
	if err != nil {
		return res, err
	}
	ids := xfer.IDs{Session: c.session, Transfer: h.TransferID}
	recvStart := time.Now()
	res.Stats, err = xfer.Receive(ctx, c.conn, c.server, ids, sink, meta.Size, c.cfg.Xfer, sink.Commit)
	res.Received = sink.Received()
	// Negociação + transferência; não conta o tempo em que o receptor ainda
	// espera FIN repetido depois do FIN_ACK (linger).
	res.Elapsed = recvStart.Sub(start) + res.Stats.Duration
	if err != nil {
		sink.Abort()
		return res, err
	}
	return res, nil
}

// Put envia o arquivo local path ao servidor, com o nome base de path. O
// servidor confere o SHA-256 antes de confirmar (FIN_ACK); se divergir, o
// erro é um *proto.RemoteError com código HASH_MISMATCH.
func (c *Client) Put(ctx context.Context, path string) (Result, error) {
	var res Result
	start := time.Now()
	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return res, err
	}
	if !info.Mode().IsRegular() {
		return res, fmt.Errorf("%s não é um arquivo regular", path)
	}
	sum, err := files.HashReader(f)
	if err != nil {
		return res, err
	}
	meta := files.NewMeta(filepath.Base(path), info.Size(), sum)
	payload, err := meta.Marshal()
	if err != nil {
		return res, err
	}
	res.Meta = meta

	h, _, err := c.call(ctx, wire.TypePut, payload, wire.TypeMetaAck)
	if err != nil {
		return res, fmt.Errorf("PUT %s: %w", meta.Name, err)
	}
	ids := xfer.IDs{Session: c.session, Transfer: h.TransferID}
	res.Stats, err = xfer.Send(ctx, c.conn, c.server, ids, f, info.Size(), c.cfg.Xfer)
	res.Elapsed = time.Since(start)
	if err != nil {
		return res, err
	}
	// FIN_ACK só é enviado depois que o servidor validou o hash.
	res.Received = sum
	return res, nil
}

// Describe traduz um erro em uma mensagem curta para o usuário.
func Describe(err error) string {
	var re *proto.RemoteError
	if errors.As(err, &re) {
		switch re.Code {
		case proto.CodeAuthFailed:
			return "senha incorreta"
		case proto.CodeNotFound:
			return "arquivo não encontrado no servidor"
		case proto.CodeExists:
			return "já existe um arquivo com esse nome no servidor"
		case proto.CodeHashMismatch:
			return "integridade falhou: o hash recebido pelo servidor difere do original (" + re.Message + ")"
		case proto.CodeNotAuthenticated:
			return "sessão inválida ou expirada"
		case proto.CodeBusy:
			return "servidor ocupado, tente de novo"
		}
		return re.Error()
	}
	if e, ok := files.IsHashMismatch(err); ok {
		return fmt.Sprintf("integridade falhou: hash original %x, hash recebido %x", e.Want, e.Got)
	}
	if errors.Is(err, control.ErrNoResponse) || errors.Is(err, xfer.ErrTimeout) {
		return "servidor não responde: " + err.Error()
	}
	if errors.Is(err, files.ErrExists) {
		return "já existe um arquivo com esse nome no destino local"
	}
	return err.Error()
}
