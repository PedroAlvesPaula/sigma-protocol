// Comando sigma-client: cliente de arquivos Sigma sobre UDP.
//
//	sigma-client [flags] probe
//	sigma-client [flags] list
//	sigma-client [flags] get NOME
//	sigma-client [flags] put CAMINHO
//
// As flags vêm antes do comando. Com vários servidores em -servers, o cliente
// mede o RTT de todos (mini-CDN) e usa o mais rápido; -server força um.
// A senha vem de SIGMA_PASSWORD ou é lida da entrada padrão.
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/client"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/discovery"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/files"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/transport"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/xfer"
)

type options struct {
	servers string
	server  string
	out     string
	window  int
	rto     time.Duration
	pings   int
	csvPath string
	loss    float64
	delay   time.Duration
}

func main() {
	var o options
	flag.StringVar(&o.servers, "servers", "127.0.0.1:9000", "servidores UDP separados por vírgula (mini-CDN)")
	flag.StringVar(&o.server, "server", "", "força um servidor, sem medir RTT (comparação manual)")
	flag.StringVar(&o.out, "o", ".", "diretório de destino dos downloads")
	flag.IntVar(&o.window, "window", xfer.DefaultConfig.Window, "janela de transmissão em blocos")
	flag.DurationVar(&o.rto, "rto", xfer.DefaultConfig.RTO, "timeout de retransmissão")
	flag.IntVar(&o.pings, "pings", 5, "PINGs por servidor na seleção")
	flag.StringVar(&o.csvPath, "csv", "", "acrescenta uma linha de métricas da transferência neste CSV")
	flag.Float64Var(&o.loss, "sim-loss", 0, "simulação: probabilidade de descartar cada datagrama enviado (0 a 1)")
	flag.DurationVar(&o.delay, "sim-delay", 0, "simulação: atraso adicionado a cada datagrama enviado")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "uso: %s [flags] probe | list | get NOME | put CAMINHO\n\nflags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, o, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "erro:", client.Describe(err))
		os.Exit(1)
	}
}

func run(ctx context.Context, o options, args []string) error {
	if len(args) == 0 {
		flag.Usage()
		return errors.New("comando ausente")
	}
	cmd := args[0]
	switch {
	case cmd == "probe" || cmd == "list":
		if len(args) != 1 {
			return fmt.Errorf("%s não recebe argumentos", cmd)
		}
	case cmd == "get" || cmd == "put":
		if len(args) != 2 {
			return fmt.Errorf("uso: %s %s", cmd, map[string]string{"get": "NOME", "put": "CAMINHO"}[cmd])
		}
	default:
		flag.Usage()
		return fmt.Errorf("comando desconhecido %q", cmd)
	}

	udp, err := net.ListenUDP("udp", nil) // porta local efêmera
	if err != nil {
		return err
	}
	udp.SetReadBuffer(8 << 20)
	udp.SetWriteBuffer(8 << 20)
	var conn transport.PacketConn = udp
	if o.loss > 0 || o.delay > 0 {
		lc, err := transport.NewLossyConn(udp, transport.LossyConfig{
			Seed: uint64(time.Now().UnixNano()),
			Send: transport.Impairment{Loss: o.loss, Delay: o.delay},
		})
		if err != nil {
			return err
		}
		conn = lc
	}
	defer conn.Close()

	server, err := chooseServer(ctx, conn, o, cmd == "probe")
	if err != nil || cmd == "probe" {
		return err
	}

	password := os.Getenv("SIGMA_PASSWORD")
	if password == "" {
		fmt.Fprint(os.Stderr, "senha: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		password = strings.TrimRight(line, "\r\n")
	}
	c := client.New(conn, server, client.Config{
		Password: password,
		Xfer:     xfer.Config{Window: o.window, RTO: o.rto},
	})
	if err := c.Login(ctx); err != nil {
		return err
	}
	fmt.Printf("autenticado em %s\n", server)

	switch cmd {
	case "list":
		entries, err := c.List(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%d arquivo(s):\n", len(entries))
		for _, e := range entries {
			fmt.Printf("  %12d  %s\n", e.Size, e.Name)
		}
		return nil
	case "get":
		if err := os.MkdirAll(o.out, 0o755); err != nil {
			return err
		}
		dst, err := files.OpenCatalog(o.out)
		if err != nil {
			return err
		}
		defer dst.Close()
		res, err := c.Get(ctx, args[1], dst)
		report("GET", server, res, err, o.csvPath)
		return err
	case "put":
		res, err := c.Put(ctx, args[1])
		report("PUT", server, res, err, o.csvPath)
		return err
	}
	return nil
}

// chooseServer aplica a seleção da mini-CDN, ou usa -server.
func chooseServer(ctx context.Context, conn transport.PacketConn, o options, verbose bool) (net.Addr, error) {
	if o.server != "" && !verbose {
		return net.ResolveUDPAddr("udp", o.server)
	}
	var addrs []net.Addr
	for _, s := range strings.Split(o.servers, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		a, err := net.ResolveUDPAddr("udp", s)
		if err != nil {
			return nil, fmt.Errorf("servidor %q: %w", s, err)
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil, errors.New("nenhum servidor em -servers")
	}
	if len(addrs) == 1 && !verbose {
		return addrs[0], nil
	}

	fmt.Printf("medindo RTT de %d servidor(es) com %d PINGs cada...\n", len(addrs), o.pings)
	results, err := discovery.Probe(ctx, conn, addrs, discovery.Config{Count: o.pings})
	if err != nil {
		return nil, err
	}
	for _, r := range results {
		var samples []string
		for _, d := range r.RTTs {
			samples = append(samples, ms(d))
		}
		status := "elegível"
		if !r.OK {
			status = "indisponível"
		}
		fmt.Printf("  %-21s mediana %8s  respostas %d/%d  [%s]  %s\n",
			r.Addr, ms(r.Median), len(r.RTTs), r.Sent, strings.Join(samples, " "), status)
	}
	best, err := discovery.Choose(results)
	if err != nil {
		return nil, err
	}
	fmt.Printf("servidor escolhido: %s (menor RTT mediano: %s)\n", results[best].Addr, ms(results[best].Median))
	return results[best].Addr, nil
}

func ms(d time.Duration) string {
	return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', 2, 64) + "ms"
}

// report imprime o resultado da transferência e, com -csv, grava as métricas.
func report(op string, server net.Addr, res client.Result, err error, csvPath string) {
	st := res.Stats
	if res.Meta.Name == "" || (err != nil && st.Duration == 0) {
		return // falhou antes de transferir: o erro é impresso por main
	}
	fmt.Printf("%s %s (%d bytes, %d blocos)\n", op, res.Meta.Name, res.Meta.Size, st.Blocks)
	fmt.Printf("  sha256 original: %s\n", hex.EncodeToString(res.Meta.SHA256[:]))
	if res.Received != ([32]byte{}) {
		fmt.Printf("  sha256 recebido: %s\n", hex.EncodeToString(res.Received[:]))
	}
	goodput := 0.0
	if st.Duration > 0 {
		goodput = float64(st.Bytes) * 8 / st.Duration.Seconds() / 1e6
	}
	fmt.Printf("  duração da transferência: %v (total com negociação: %v)\n",
		st.Duration.Round(time.Millisecond), res.Elapsed.Round(time.Millisecond))
	fmt.Printf("  goodput: %.2f Mbit/s\n", goodput)
	if op == "PUT" {
		fmt.Printf("  DATA enviados: %d, retransmissões: %d\n", st.DataSent, st.Retransmissions)
	} else {
		fmt.Printf("  DATA recebidos: %d, duplicados: %d, corrompidos descartados: %d\n",
			st.DataReceived, st.Duplicates, st.Corrupt)
	}
	status := "ok"
	if err != nil {
		status = "erro: " + client.Describe(err)
	} else {
		fmt.Println("  integridade: OK (hashes iguais)")
	}
	if csvPath != "" {
		if werr := appendCSV(csvPath, op, server, res, goodput, status); werr != nil {
			fmt.Fprintln(os.Stderr, "aviso: CSV:", werr)
		}
	}
}

var csvHeader = []string{"timestamp", "op", "server", "file", "bytes", "blocks", "duration_s", "elapsed_s",
	"goodput_mbps", "data_sent", "retransmissions", "data_received", "duplicates", "corrupt",
	"sha256_original", "sha256_received", "status"}

func appendCSV(path, op string, server net.Addr, res client.Result, goodput float64, status string) error {
	_, statErr := os.Stat(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if errors.Is(statErr, os.ErrNotExist) {
		w.Write(csvHeader)
	}
	st := res.Stats
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	w.Write([]string{
		time.Now().Format(time.RFC3339), op, server.String(), res.Meta.Name,
		strconv.FormatInt(res.Meta.Size, 10), strconv.FormatUint(uint64(st.Blocks), 10),
		strconv.FormatFloat(st.Duration.Seconds(), 'f', 4, 64),
		strconv.FormatFloat(res.Elapsed.Seconds(), 'f', 4, 64),
		strconv.FormatFloat(goodput, 'f', 3, 64),
		u(st.DataSent), u(st.Retransmissions), u(st.DataReceived), u(st.Duplicates), u(st.Corrupt),
		hex.EncodeToString(res.Meta.SHA256[:]), hex.EncodeToString(res.Received[:]), status,
	})
	w.Flush()
	return w.Error()
}
