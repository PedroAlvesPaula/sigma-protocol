// Comando sigma-server: servidor de arquivos Sigma sobre UDP.
//
//	SIGMA_PASSWORD=segredo sigma-server -bind :9000 -dir ./shared
//
// A senha vem da variável de ambiente SIGMA_PASSWORD (não de flag, para não
// aparecer em `ps` nem no histórico do shell).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/files"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/server"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/transport"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/xfer"
)

func main() {
	bind := flag.String("bind", "127.0.0.1:9000", "endereço UDP do servidor (use :9000 para todas as interfaces)")
	dir := flag.String("dir", "./shared", "diretório de arquivos compartilhados (recebe também os uploads)")
	window := flag.Int("window", xfer.DefaultConfig.Window, "janela de transmissão em blocos")
	rto := flag.Duration("rto", xfer.DefaultConfig.RTO, "timeout de retransmissão")
	debug := flag.Bool("v", false, "log detalhado")
	// Simulação de rede na própria aplicação (para testes sem tc netem).
	loss := flag.Float64("sim-loss", 0, "simulação: probabilidade de descartar cada datagrama enviado (0 a 1)")
	delay := flag.Duration("sim-delay", 0, "simulação: atraso adicionado a cada datagrama enviado")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := run(log, *bind, *dir, *window, *rto, *loss, *delay); err != nil {
		log.Error("encerrando", "erro", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, bind, dir string, window int, rto time.Duration, loss float64, delay time.Duration) error {
	password := os.Getenv("SIGMA_PASSWORD")
	if password == "" {
		return fmt.Errorf("defina a senha em SIGMA_PASSWORD")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cat, err := files.OpenCatalog(dir)
	if err != nil {
		return err
	}
	defer cat.Close()

	addr, err := net.ResolveUDPAddr("udp", bind)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	// Buffers maiores reduzem descartes no socket com janelas grandes.
	udp.SetReadBuffer(8 << 20)
	udp.SetWriteBuffer(8 << 20)

	var conn transport.PacketConn = udp
	if loss > 0 || delay > 0 {
		lc, err := transport.NewLossyConn(udp, transport.LossyConfig{
			Seed: uint64(time.Now().UnixNano()),
			Send: transport.Impairment{Loss: loss, Delay: delay},
		})
		if err != nil {
			return err
		}
		conn = lc
		log.Warn("simulação de rede ativa", "perda", loss, "atraso", delay)
	}
	defer conn.Close()

	srv, err := server.New(conn, server.Config{
		Catalog:  cat,
		Password: password,
		Xfer:     xfer.Config{Window: window, RTO: rto},
		Logger:   log,
	})
	if err != nil {
		return err
	}
	log.Info("calculando SHA-256 dos arquivos", "diretório", dir)
	if err := srv.WarmHashes(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("servidor no ar", "endereço", udp.LocalAddr().String(), "janela", window)
	return srv.Serve(ctx)
}
