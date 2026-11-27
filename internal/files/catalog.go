package files

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxNameLen é o tamanho máximo, em bytes UTF-8, de um nome de arquivo.
const MaxNameLen = 255

// tmpPrefix marca arquivos temporários; nomes que começam com "." ficam fora
// do catálogo e não podem ser pedidos pelo cliente.
const tmpPrefix = ".sigma-tmp-"

// Erros do pacote. Use errors.Is; cada um corresponde a um código de ERROR
// do protocolo (ver docs/protocolo.md).
var (
	ErrInvalidName  = errors.New("files: nome de arquivo inválido")
	ErrNotFound     = errors.New("files: arquivo não encontrado")
	ErrExists       = errors.New("files: arquivo já existe")
	ErrTooLarge     = errors.New("files: arquivo excede o tamanho máximo")
	ErrSizeMismatch = errors.New("files: tamanho recebido difere do anunciado")
)

// ValidateName aceita apenas um nome simples (um único componente de
// caminho): sem separadores, sem "." inicial, sem caracteres de controle,
// UTF-8 válido e com no máximo MaxNameLen bytes.
func ValidateName(name string) error {
	switch {
	case name == "", len(name) > MaxNameLen:
		return fmt.Errorf("%w: tamanho %d", ErrInvalidName, len(name))
	case !utf8.ValidString(name):
		return fmt.Errorf("%w: UTF-8 inválido", ErrInvalidName)
	case strings.ContainsAny(name, `/\`):
		return fmt.Errorf("%w: %q contém separador de caminho", ErrInvalidName, name)
	case strings.HasPrefix(name, "."):
		return fmt.Errorf("%w: %q começa com ponto", ErrInvalidName, name)
	case strings.ContainsFunc(name, unicode.IsControl):
		return fmt.Errorf("%w: %q contém caractere de controle", ErrInvalidName, name)
	}
	return nil
}

// Entry descreve um arquivo do catálogo.
type Entry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Catalog dá acesso aos arquivos de um diretório. Todo acesso passa por
// os.Root, que impede sair do diretório inclusive por links simbólicos.
// É seguro para uso concorrente.
type Catalog struct {
	root *os.Root

	mu     sync.Mutex
	hashes map[string]cachedHash
}

type cachedHash struct {
	size  int64
	mtime time.Time
	sum   [sha256.Size]byte
}

// OpenCatalog abre o diretório dir. Feche com Close.
func OpenCatalog(dir string) (*Catalog, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("files: abrindo diretório %q: %w", dir, err)
	}
	return &Catalog{root: root, hashes: map[string]cachedHash{}}, nil
}

// Dir retorna o caminho do diretório do catálogo.
func (c *Catalog) Dir() string { return c.root.Name() }

// Close libera o diretório. Arquivos já abertos continuam válidos.
func (c *Catalog) Close() error { return c.root.Close() }

// List retorna os arquivos regulares do diretório, em ordem de nome. Links
// simbólicos, subdiretórios e arquivos ocultos/temporários são omitidos.
func (c *Catalog) List() ([]Entry, error) {
	d, err := c.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	des, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(des))
	for _, de := range des {
		if !de.Type().IsRegular() || ValidateName(de.Name()) != nil {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue // removido entre ReadDir e Info
		}
		out = append(out, Entry{Name: de.Name(), Size: info.Size()})
	}
	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Open abre o arquivo regular name para leitura. O *os.File retornado
// implementa io.ReaderAt e pode ser passado diretamente ao transporte.
func (c *Catalog) Open(name string) (*os.File, int64, error) {
	if err := ValidateName(name); err != nil {
		return nil, 0, err
	}
	f, err := c.root.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, fmt.Errorf("%w: %q", ErrNotFound, name)
		}
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, 0, fmt.Errorf("%w: %q não é um arquivo regular", ErrNotFound, name)
	}
	if info.Size() > MaxFileSize {
		f.Close()
		return nil, 0, fmt.Errorf("%w: %q", ErrTooLarge, name)
	}
	return f, info.Size(), nil
}

// Hash retorna o SHA-256 do arquivo name. O resultado fica em cache enquanto
// tamanho e data de modificação não mudarem, para não reler 80 MB a cada GET.
func (c *Catalog) Hash(name string) ([sha256.Size]byte, error) {
	f, _, err := c.Open(name)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	c.mu.Lock()
	ch, ok := c.hashes[name]
	c.mu.Unlock()
	if ok && ch.size == info.Size() && ch.mtime.Equal(info.ModTime()) {
		return ch.sum, nil
	}

	sum, err := HashReader(f)
	if err != nil {
		return sum, err
	}
	c.mu.Lock()
	c.hashes[name] = cachedHash{size: info.Size(), mtime: info.ModTime(), sum: sum}
	c.mu.Unlock()
	return sum, nil
}

// exists informa se name já existe no diretório (qualquer tipo).
func (c *Catalog) exists(name string) (bool, error) {
	_, err := c.root.Lstat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// HashReader calcula o SHA-256 de tudo que r produz.
func HashReader(r io.Reader) ([sha256.Size]byte, error) {
	h := sha256.New()
	var sum [sha256.Size]byte
	if _, err := io.Copy(h, r); err != nil {
		return sum, err
	}
	h.Sum(sum[:0])
	return sum, nil
}

// HashFile calcula o SHA-256 do arquivo em path (usado pelo cliente no PUT,
// fora de um Catalog).
func HashFile(path string) ([sha256.Size]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer f.Close()
	return HashReader(f)
}
