package files

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
)

// HashMismatchError indica que o SHA-256 do arquivo recebido difere do
// anunciado no META. Traz os dois valores para log e relatório.
type HashMismatchError struct {
	Want, Got [sha256.Size]byte
}

func (e *HashMismatchError) Error() string {
	return fmt.Sprintf("files: hash divergente: original %x, recebido %x", e.Want, e.Got)
}

// Sink grava um arquivo recebido em um temporário no diretório do catálogo,
// calculando o SHA-256 em paralelo à escrita. Commit valida tamanho e hash e
// só então publica o arquivo com o nome final; Abort descarta tudo.
//
// O transporte deve escrever os blocos em ordem (o receptor só entrega o
// prefixo contíguo). Sink não é seguro para uso concorrente.
type Sink struct {
	cat  *Catalog
	name string
	tmp  string
	size int64
	want [sha256.Size]byte

	f       *os.File
	bw      *bufio.Writer
	h       hash.Hash
	w       io.Writer
	written int64
	got     [sha256.Size]byte
	done    bool
}

var _ io.Writer = (*Sink)(nil)

// NewSink prepara o recebimento de name com size bytes e hash want. Falha com
// ErrExists se name já existir (upload não sobrescreve arquivos).
func (c *Catalog) NewSink(name string, size int64, want [sha256.Size]byte) (*Sink, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if size < 0 || size > MaxFileSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, size)
	}
	if ok, err := c.exists(name); err != nil {
		return nil, err
	} else if ok {
		return nil, fmt.Errorf("%w: %q", ErrExists, name)
	}

	var rnd [8]byte
	rand.Read(rnd[:])
	tmp := tmpPrefix + hex.EncodeToString(rnd[:])
	f, err := c.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, fmt.Errorf("files: criando temporário: %w", err)
	}
	s := &Sink{cat: c, name: name, tmp: tmp, size: size, want: want, f: f,
		bw: bufio.NewWriterSize(f, 256<<10), h: sha256.New()}
	s.w = io.MultiWriter(s.bw, s.h)
	return s, nil
}

// Name retorna o nome final do arquivo.
func (s *Sink) Name() string { return s.name }

// Written retorna quantos bytes já foram gravados.
func (s *Sink) Written() int64 { return s.written }

// Write grava p no temporário. Gravar além do tamanho anunciado é erro.
func (s *Sink) Write(p []byte) (int, error) {
	if s.done {
		return 0, os.ErrClosed
	}
	if s.written+int64(len(p)) > s.size {
		return 0, fmt.Errorf("%w: mais de %d bytes", ErrSizeMismatch, s.size)
	}
	n, err := s.w.Write(p)
	s.written += int64(n)
	return n, err
}

// Commit finaliza o recebimento: confere tamanho e SHA-256, sincroniza o
// temporário em disco e o renomeia para o nome final. Em qualquer falha o
// temporário é apagado. O hash recebido fica disponível em Received, inclusive
// após falha de hash.
func (s *Sink) Commit() error {
	if s.done {
		return os.ErrClosed
	}
	s.done = true
	err := s.finish()
	if err != nil {
		s.f.Close()
		s.cat.root.Remove(s.tmp)
	}
	return err
}

func (s *Sink) finish() error {
	s.h.Sum(s.got[:0])
	if s.written != s.size {
		return fmt.Errorf("%w: recebidos %d de %d bytes", ErrSizeMismatch, s.written, s.size)
	}
	if s.got != s.want {
		return &HashMismatchError{Want: s.want, Got: s.got}
	}
	if err := s.bw.Flush(); err != nil {
		return err
	}
	if err := s.f.Sync(); err != nil {
		return err
	}
	if err := s.f.Close(); err != nil {
		return err
	}
	// Rename substituiria um arquivo criado por outro upload durante a
	// transferência; confere de novo para não sobrescrever.
	if ok, err := s.cat.exists(s.name); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("%w: %q", ErrExists, s.name)
	}
	return s.cat.root.Rename(s.tmp, s.name)
}

// Abort descarta o recebimento e apaga o temporário. Pode ser chamado mais de
// uma vez e depois de Commit (não faz nada nesse caso).
func (s *Sink) Abort() error {
	if s.done {
		return nil
	}
	s.done = true
	s.f.Close()
	return s.cat.root.Remove(s.tmp)
}

// Received retorna o SHA-256 dos bytes recebidos; válido após Commit.
func (s *Sink) Received() [sha256.Size]byte { return s.got }

// IsHashMismatch extrai um *HashMismatchError de err.
func IsHashMismatch(err error) (*HashMismatchError, bool) {
	var e *HashMismatchError
	ok := errors.As(err, &e)
	return e, ok
}
