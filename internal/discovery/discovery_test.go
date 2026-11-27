package discovery_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/discovery"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/files"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/server"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/transport"
)

// startServer sobe um servidor real em 127.0.0.1 (porta livre), com atraso
// opcional nas respostas.
func startServer(t *testing.T, delay time.Duration) net.Addr {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var conn transport.PacketConn = udp
	if delay > 0 {
		if conn, err = transport.NewLossyConn(udp, transport.LossyConfig{Send: transport.Impairment{Delay: delay}}); err != nil {
			t.Fatal(err)
		}
	}
	cat, err := files.OpenCatalog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(conn, server.Config{Catalog: cat, Password: "x",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; conn.Close(); cat.Close() })
	return udp.LocalAddr()
}

func clientConn(t *testing.T) transport.PacketConn {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	return udp
}

func TestChoosesFastest(t *testing.T) {
	slow := startServer(t, 30*time.Millisecond)
	fast := startServer(t, 0)
	cfg := discovery.Config{Count: 5, Timeout: 500 * time.Millisecond}

	res, err := discovery.Probe(context.Background(), clientConn(t), []net.Addr{slow, fast}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if !r.OK || len(r.RTTs) != 5 {
			t.Fatalf("%v: %d respostas", r.Addr, len(r.RTTs))
		}
	}
	if res[0].Median < 30*time.Millisecond {
		t.Fatalf("RTT do servidor lento = %v, esperado >= 30ms", res[0].Median)
	}
	best, err := discovery.Choose(res)
	if err != nil || res[best].Addr.String() != fast.String() {
		t.Fatalf("escolheu %v (err %v), esperado %v", res[best].Addr, err, fast)
	}
}

func TestUnavailableServer(t *testing.T) {
	up := startServer(t, 0)
	// Porta sem servidor: os PINGs ficam sem resposta.
	dead := clientConn(t).LocalAddr()
	cfg := discovery.Config{Count: 3, Timeout: 100 * time.Millisecond}

	res, err := discovery.Probe(context.Background(), clientConn(t), []net.Addr{dead, up}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].OK || res[0].Lost() != 3 {
		t.Fatalf("servidor inexistente: %+v", res[0])
	}
	if best, err := discovery.Choose(res); err != nil || best != 1 {
		t.Fatalf("escolha %d, %v", best, err)
	}

	res, _ = discovery.Probe(context.Background(), clientConn(t), []net.Addr{dead}, cfg)
	if _, err := discovery.Choose(res); !errors.Is(err, discovery.ErrNoServer) {
		t.Fatalf("esperado ErrNoServer, obtido %v", err)
	}
}

func TestChooseTieAndMedian(t *testing.T) {
	ms := time.Millisecond
	res := []discovery.Result{
		{OK: true, Median: 10 * ms},
		{OK: true, Median: 10 * ms},
		{OK: false, Median: 1 * ms},
	}
	if best, _ := discovery.Choose(res); best != 0 {
		t.Fatalf("empate deve escolher o primeiro, escolheu %d", best)
	}
	if m := discovery.Median([]time.Duration{5 * ms, 1 * ms, 100 * ms}); m != 5*ms {
		t.Fatalf("mediana ímpar = %v", m)
	}
	if m := discovery.Median([]time.Duration{4 * ms, 2 * ms}); m != 3*ms {
		t.Fatalf("mediana par = %v", m)
	}
}
