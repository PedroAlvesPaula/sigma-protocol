// Package discovery implementa a seleção de servidor da mini-CDN: o cliente
// envia PINGs a todos os servidores configurados, mede o RTT de cada um no
// relógio local e escolhe o de menor RTT mediano.
//
// Diferente de uma CDN real, não há DNS, anycast nem informação de carga: a
// decisão é tomada só pelo cliente, com medição ativa (ver docs/aplicacao.md).
package discovery

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"time"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/auth"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/proto"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/transport"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/wire"
)

// Config parametriza a sondagem.
type Config struct {
	Count      int           // PINGs por servidor (padrão 5)
	Timeout    time.Duration // espera máxima por rodada (padrão 1 s)
	MinReplies int           // PONGs necessários para o servidor ser elegível (padrão 3)
}

func (c Config) withDefaults() Config {
	if c.Count <= 0 {
		c.Count = 5
	}
	if c.Timeout <= 0 {
		c.Timeout = time.Second
	}
	if c.MinReplies <= 0 {
		c.MinReplies = min(3, c.Count)
	}
	return c
}

// Result é a medição de um servidor.
type Result struct {
	Addr   net.Addr
	Sent   int
	RTTs   []time.Duration // uma amostra por PONG válido, na ordem de chegada
	Median time.Duration   // mediana de RTTs; 0 se não houve resposta
	OK     bool            // recebeu pelo menos MinReplies PONGs
}

// Lost retorna quantos PINGs ficaram sem resposta.
func (r Result) Lost() int { return r.Sent - len(r.RTTs) }

type pending struct {
	server int
	nonce  string
	sent   time.Time
}

// Probe mede o RTT de cada servidor. Em cada rodada envia um PING a todos e
// espera as respostas até cfg.Timeout; PONGs atrasados de rodadas anteriores
// ainda contam (o RTT é medido a partir do envio do próprio PING).
//
// Cada PING tem Seq único e nonce aleatório; o PONG precisa ecoar os dois e
// vir do endereço para o qual o PING foi enviado.
func Probe(ctx context.Context, conn transport.PacketConn, servers []net.Addr, cfg Config) ([]Result, error) {
	cfg = cfg.withDefaults()
	results := make([]Result, len(servers))
	for i, s := range servers {
		results[i].Addr = s
	}
	defer conn.SetReadDeadline(time.Time{})

	out := make([]byte, wire.MaxDatagram)
	in := make([]byte, 64*1024)
	waiting := map[uint32]pending{}
	var seq uint32

	for range cfg.Count {
		round := map[uint32]bool{}
		for i, s := range servers {
			seq++
			nonce := hex.EncodeToString(auth.NewNonce()[:16])
			payload, _ := proto.Marshal(proto.Ping{Nonce: nonce})
			n, err := wire.Encode(out, wire.Header{Type: wire.TypePing, Seq: seq}, payload)
			if err != nil {
				return nil, err
			}
			waiting[seq] = pending{server: i, nonce: nonce, sent: time.Now()}
			round[seq] = true
			results[i].Sent++
			if _, err := conn.WriteTo(out[:n], s); err != nil {
				// Servidor inalcançável (ex.: endereço inválido): conta como perda.
				delete(round, seq)
			}
		}

		deadline := time.Now().Add(cfg.Timeout)
		conn.SetReadDeadline(deadline)
		for len(round) > 0 {
			if err := ctx.Err(); err != nil {
				return results, err
			}
			n, addr, err := conn.ReadFrom(in)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil {
				// Ex.: ICMP "port unreachable" em UDP conectado; ignora.
				if time.Now().After(deadline) {
					break
				}
				continue
			}
			now := time.Now()
			h, p, err := wire.Decode(in[:n])
			if err != nil || h.Type != wire.TypePong {
				continue
			}
			pd, ok := waiting[h.Ack]
			if !ok || addr == nil || addr.String() != servers[pd.server].String() {
				continue
			}
			var pong proto.Ping
			if proto.Unmarshal(p, &pong) != nil || pong.Nonce != pd.nonce {
				continue
			}
			delete(waiting, h.Ack)
			delete(round, h.Ack)
			results[pd.server].RTTs = append(results[pd.server].RTTs, now.Sub(pd.sent))
		}
	}

	for i := range results {
		results[i].Median = Median(results[i].RTTs)
		results[i].OK = len(results[i].RTTs) >= cfg.MinReplies
	}
	return results, nil
}

// ErrNoServer indica que nenhum servidor respondeu o suficiente.
var ErrNoServer = errors.New("nenhum servidor disponível")

// Choose retorna o índice do servidor elegível (OK) de menor RTT mediano. Em
// empate vence o que aparece primeiro na configuração.
func Choose(results []Result) (int, error) {
	best := -1
	for i, r := range results {
		if r.OK && (best < 0 || r.Median < results[best].Median) {
			best = i
		}
	}
	if best < 0 {
		return -1, fmt.Errorf("%w: nenhum respondeu a PINGs suficientes", ErrNoServer)
	}
	return best, nil
}

// Median retorna a mediana das amostras (0 se vazio).
func Median(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	m := len(s) / 2
	if len(s)%2 == 1 {
		return s[m]
	}
	return (s[m-1] + s[m]) / 2
}
