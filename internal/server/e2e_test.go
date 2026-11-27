package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/client"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/control"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/files"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/proto"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/server"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/transport"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/wire"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/xfer"
)

const password = "senha-de-teste"

// Parâmetros curtos para os testes com perda terminarem rápido.
var (
	testXfer    = xfer.Config{RTO: 20 * time.Millisecond, MaxRetries: 30, Linger: 100 * time.Millisecond}
	testControl = control.Config{Timeout: 50 * time.Millisecond, MaxTimeout: 200 * time.Millisecond, Attempts: 20}
)

type env struct {
	serverDir, clientDir string
	srvCat, cliCat       *files.Catalog
	client               *client.Client
	srvConn              transport.PacketConn
}

// setup sobe um servidor e um cliente ligados por um Pipe em memória com as
// falhas im aplicadas nos dois sentidos.
func setup(t *testing.T, im transport.Impairment, pass string) *env {
	t.Helper()
	e := &env{serverDir: t.TempDir(), clientDir: t.TempDir()}
	a, b := transport.Pipe(0)
	var sc, cc transport.PacketConn = a, b
	if im != (transport.Impairment{}) {
		var err error
		if sc, err = transport.NewLossyConn(a, transport.LossyConfig{Seed: 1, Send: im}); err != nil {
			t.Fatal(err)
		}
		if cc, err = transport.NewLossyConn(b, transport.LossyConfig{Seed: 2, Send: im}); err != nil {
			t.Fatal(err)
		}
	}
	e.srvConn = sc

	var err error
	if e.srvCat, err = files.OpenCatalog(e.serverDir); err != nil {
		t.Fatal(err)
	}
	if e.cliCat, err = files.OpenCatalog(e.clientDir); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	srv, err := server.New(sc, server.Config{Catalog: e.srvCat, Password: password, Xfer: testXfer, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
		sc.Close()
		cc.Close()
		e.srvCat.Close()
		e.cliCat.Close()
	})

	e.client = client.New(cc, nil, client.Config{Password: pass, Control: testControl, Xfer: testXfer})
	return e
}

func writeRandom(t *testing.T, path string, n int) []byte {
	t.Helper()
	rng := rand.New(rand.NewPCG(uint64(n), 7))
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(rng.Uint32())
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return data
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestFullFlow(t *testing.T) {
	scenarios := map[string]transport.Impairment{
		"sem perda": {},
		// 5% de perda por sentido, duplicação, corrupção e reordenação.
		"com falhas": {Loss: 0.05, Duplicate: 0.02, Corrupt: 0.02, Delay: time.Millisecond, Jitter: 2 * time.Millisecond},
	}
	for name, im := range scenarios {
		t.Run(name, func(t *testing.T) {
			e := setup(t, im, password)
			ctx := ctxT(t)
			data := writeRandom(t, filepath.Join(e.serverDir, "dados.bin"), 300_000)
			writeRandom(t, filepath.Join(e.serverDir, "vazio.txt"), 0)

			if err := e.client.Login(ctx); err != nil {
				t.Fatalf("Login: %v", err)
			}
			list, err := e.client.List(ctx)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(list) != 2 || list[0] != (files.Entry{Name: "dados.bin", Size: 300_000}) {
				t.Fatalf("List = %+v", list)
			}

			// Download
			res, err := e.client.Get(ctx, "dados.bin", e.cliCat)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if res.Received != sha256.Sum256(data) || res.Meta.SHA256 != res.Received {
				t.Fatal("hashes divergentes")
			}
			got, _ := os.ReadFile(filepath.Join(e.clientDir, "dados.bin"))
			if !bytes.Equal(got, data) {
				t.Fatal("conteúdo baixado difere")
			}
			if _, err := e.client.Get(ctx, "vazio.txt", e.cliCat); err != nil {
				t.Fatalf("Get vazio: %v", err)
			}

			// Upload
			up := writeRandom(t, filepath.Join(t.TempDir(), "envio.bin"), 50_000)
			if _, err := e.client.Put(ctx, filepath.Join(filepath.Dir(e.clientDir), "x")); err == nil {
				t.Fatal("Put de arquivo inexistente deveria falhar")
			}
			upPath := filepath.Join(e.clientDir, "envio.bin")
			os.WriteFile(upPath, up, 0o644)
			if _, err := e.client.Put(ctx, upPath); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got, _ = os.ReadFile(filepath.Join(e.serverDir, "envio.bin"))
			if !bytes.Equal(got, up) {
				t.Fatal("conteúdo enviado difere")
			}

			// Erros de aplicação
			if _, err := e.client.Get(ctx, "nao-existe", e.cliCat); !proto.IsCode(err, proto.CodeNotFound) {
				t.Fatalf("GET inexistente: %v", err)
			}
			if _, err := e.client.Get(ctx, "../segredo", e.cliCat); !proto.IsCode(err, proto.CodeBadRequest) {
				t.Fatalf("GET com traversal: %v", err)
			}
			if _, err := e.client.Put(ctx, upPath); !proto.IsCode(err, proto.CodeExists) {
				t.Fatalf("PUT repetido: %v", err)
			}
		})
	}
}

func TestWrongPassword(t *testing.T) {
	e := setup(t, transport.Impairment{}, "senha-errada")
	ctx := ctxT(t)
	err := e.client.Login(ctx)
	if !proto.IsCode(err, proto.CodeAuthFailed) {
		t.Fatalf("esperado AUTH_FAILED, obtido %v", err)
	}
	// Sem autenticação, operações são recusadas.
	if _, err := e.client.List(ctx); !proto.IsCode(err, proto.CodeNotAuthenticated) {
		t.Fatalf("LIST sem autenticação: %v", err)
	}
}

// Um servidor que corrompe o arquivo (hash anunciado errado) faz o cliente
// recusar o download e não deixar arquivo no destino.
func TestGetHashMismatch(t *testing.T) {
	e := setup(t, transport.Impairment{}, password)
	ctx := ctxT(t)
	path := filepath.Join(e.serverDir, "f.bin")
	writeRandom(t, path, 10_000)
	if err := e.client.Login(ctx); err != nil {
		t.Fatal(err)
	}
	// Preenche o cache de hash e altera o arquivo mantendo tamanho e mtime.
	info, _ := os.Stat(path)
	e.srvCat.Hash("f.bin")
	writeRandom(t, path, 10_001)
	os.Truncate(path, 10_000)
	os.Chtimes(path, info.ModTime(), info.ModTime())

	_, err := e.client.Get(ctx, "f.bin", e.cliCat)
	if mm, ok := files.IsHashMismatch(err); !ok || mm.Want == mm.Got {
		t.Fatalf("esperado HashMismatchError, obtido %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.clientDir, "f.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("arquivo corrompido ficou no destino")
	}
}

func TestListPagination(t *testing.T) {
	var entries []files.Entry
	for i := range 200 {
		entries = append(entries, files.Entry{Name: strings.Repeat("n", 40) + string(rune('a'+i%26)), Size: int64(i)})
	}
	var all []files.Entry
	offset := 0
	pages := 0
	for offset >= 0 {
		p, err := server.ListPage(entries, offset)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) > wire.MaxPayload {
			t.Fatalf("página com %d bytes", len(p))
		}
		var res proto.ListResult
		if err := proto.Unmarshal(p, &res); err != nil {
			t.Fatal(err)
		}
		all = append(all, res.Files...)
		offset = res.Next
		pages++
	}
	if len(all) != len(entries) || pages < 2 {
		t.Fatalf("%d entradas em %d páginas", len(all), pages)
	}
}
