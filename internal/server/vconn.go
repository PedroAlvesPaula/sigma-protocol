package server

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/transport"
)

// vconn é a conexão virtual de UMA transferência no servidor.
//
// O servidor tem um único socket UDP para todos os clientes. O laço principal
// (Server.Serve) lê esse socket e coloca na fila de cada vconn os datagramas
// da transferência correspondente. Para o transporte, vconn se comporta como
// um socket exclusivo: ReadFrom só devolve datagramas daquela transferência e
// WriteTo escreve direto no socket compartilhado. Assim o mesmo código de
// transporte serve para cliente, servidor e testes.
type vconn struct {
	sock transport.PacketConn
	peer net.Addr
	ch   chan []byte

	closeOnce sync.Once
	closed    chan struct{}

	mu       sync.Mutex
	deadline time.Time
}

var _ transport.PacketConn = (*vconn)(nil)

// vconnQueue é a capacidade da fila; cheia, novos datagramas são descartados
// (como no buffer de recepção de um socket) e o transporte os recupera.
const vconnQueue = 4096

func newVConn(sock transport.PacketConn, peer net.Addr) *vconn {
	return &vconn{sock: sock, peer: peer, ch: make(chan []byte, vconnQueue), closed: make(chan struct{})}
}

// push entrega um datagrama (já copiado) sem bloquear o laço principal.
func (v *vconn) push(b []byte) {
	select {
	case v.ch <- b:
	default:
	}
}

func (v *vconn) ReadFrom(p []byte) (int, net.Addr, error) {
	v.mu.Lock()
	deadline := v.deadline
	v.mu.Unlock()

	var timeout <-chan time.Time
	if !deadline.IsZero() {
		wait := time.Until(deadline)
		if wait <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case b := <-v.ch:
		return copy(p, b), v.peer, nil
	case <-v.closed:
		return 0, nil, net.ErrClosed
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (v *vconn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-v.closed:
		return 0, net.ErrClosed
	default:
	}
	return v.sock.WriteTo(p, v.peer)
}

// SetReadDeadline vale para a próxima chamada de ReadFrom (o transporte
// sempre define o prazo antes de ler).
func (v *vconn) SetReadDeadline(t time.Time) error {
	v.mu.Lock()
	v.deadline = t
	v.mu.Unlock()
	return nil
}

func (v *vconn) LocalAddr() net.Addr { return v.sock.LocalAddr() }

func (v *vconn) Close() error {
	v.closeOnce.Do(func() { close(v.closed) })
	return nil
}
