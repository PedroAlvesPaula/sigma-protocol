package files

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func randomBytes(n int, seed uint64) []byte {
	rng := rand.New(rand.NewPCG(seed, 0))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

func openCat(t *testing.T, dir string) *Catalog {
	t.Helper()
	c, err := OpenCatalog(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, de := range des {
		names = append(names, de.Name())
	}
	return names
}

func TestNumBlocksAndRange(t *testing.T) {
	cases := []struct {
		size int64
		want uint32
	}{{0, 0}, {1, 1}, {BlockSize, 1}, {BlockSize + 1, 2}, {83886080, 72566}}
	for _, c := range cases {
		if got := NumBlocks(c.size); got != c.want {
			t.Errorf("NumBlocks(%d) = %d, esperado %d", c.size, got, c.want)
		}
	}
	// A soma dos blocos cobre o arquivo exatamente.
	size := int64(3*BlockSize + 7)
	var total int64
	for i := range NumBlocks(size) {
		off, n := BlockRange(i, size)
		if off != total {
			t.Fatalf("bloco %d começa em %d, esperado %d", i, off, total)
		}
		total += int64(n)
	}
	if total != size {
		t.Fatalf("blocos cobrem %d de %d bytes", total, size)
	}
	if _, n := BlockRange(NumBlocks(size), size); n != 0 {
		t.Fatalf("bloco além do fim com %d bytes", n)
	}
}

func TestValidateName(t *testing.T) {
	ok := []string{"teste.bin", "relatório final.pdf", "a", strings.Repeat("x", MaxNameLen)}
	bad := []string{"", ".", "..", "../etc/passwd", "a/b", `a\b`, "/abs", ".oculto",
		".sigma-tmp-1", "a\x00b", "a\nb", "\xff", strings.Repeat("x", MaxNameLen+1)}
	for _, n := range ok {
		if err := ValidateName(n); err != nil {
			t.Errorf("%q rejeitado: %v", n, err)
		}
	}
	for _, n := range bad {
		if err := ValidateName(n); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q aceito (err=%v)", n, err)
		}
	}
}

func TestCatalogListAndOpen(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "b.bin"), []byte("bbb"), 0o644)
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644)
	os.WriteFile(filepath.Join(dir, ".oculto"), []byte("x"), 0o644)
	os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	os.Symlink("a.txt", filepath.Join(dir, "link"))
	c := openCat(t, dir)

	got, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{"a.txt", 1}, {"b.bin", 3}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("List = %+v, esperado %+v", got, want)
	}

	f, size, err := c.Open("b.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 2)
	if _, err := f.ReadAt(buf, 1); err != nil || size != 3 || string(buf) != "bb" {
		t.Fatalf("ReadAt: %q size=%d err=%v", buf, size, err)
	}

	if _, _, err := c.Open("nao-existe"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("inexistente: %v", err)
	}
	if _, _, err := c.Open("sub"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("diretório: %v", err)
	}
	if _, _, err := c.Open("../x"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("traversal: %v", err)
	}
}

// Um link simbólico que aponta para fora do diretório não pode ser lido.
func TestCatalogSymlinkEscape(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "segredo")
	os.WriteFile(secret, []byte("senha"), 0o644)
	dir := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(dir, "fuga")); err != nil {
		t.Skip("symlink indisponível:", err)
	}
	c := openCat(t, dir)
	if f, _, err := c.Open("fuga"); err == nil {
		f.Close()
		t.Fatal("link para fora do diretório foi aberto")
	}
}

func TestHashCache(t *testing.T) {
	dir := t.TempDir()
	data := randomBytes(10_000, 1)
	path := filepath.Join(dir, "f")
	os.WriteFile(path, data, 0o644)
	c := openCat(t, dir)

	h1, err := c.Hash("f")
	if err != nil || h1 != sha256.Sum256(data) {
		t.Fatalf("hash errado: %v", err)
	}
	if h2, _ := HashFile(path); h2 != h1 {
		t.Fatal("HashFile diverge de Catalog.Hash")
	}
	// Conteúdo alterado (tamanho diferente) invalida o cache.
	os.WriteFile(path, data[:5000], 0o644)
	if h3, _ := c.Hash("f"); h3 != sha256.Sum256(data[:5000]) {
		t.Fatal("cache não foi invalidado")
	}
}

// Transfere arquivos de vários tamanhos bloco a bloco, como o transporte fará:
// ReadAt no emissor, Write em ordem no receptor.
func TestSinkRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, BlockSize, BlockSize + 1, 5 << 20} {
		src := t.TempDir()
		dst := t.TempDir()
		data := randomBytes(size, uint64(size))
		os.WriteFile(filepath.Join(src, "arq.bin"), data, 0o644)
		cs, cd := openCat(t, src), openCat(t, dst)

		f, n, err := cs.Open("arq.bin")
		if err != nil {
			t.Fatal(err)
		}
		sum, _ := cs.Hash("arq.bin")
		meta := NewMeta("arq.bin", n, sum)
		payload, err := meta.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := UnmarshalMeta(payload)
		if err != nil || got != meta {
			t.Fatalf("META round-trip: %+v %v", got, err)
		}

		sink, err := cd.NewSink(got.Name, got.Size, got.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, BlockSize)
		for i := range got.Blocks() {
			off, k := BlockRange(i, got.Size)
			if _, err := f.ReadAt(buf[:k], off); err != nil && err != io.EOF {
				t.Fatal(err)
			}
			if _, err := sink.Write(buf[:k]); err != nil {
				t.Fatal(err)
			}
		}
		f.Close()
		if err := sink.Commit(); err != nil {
			t.Fatalf("%d bytes: Commit: %v", size, err)
		}
		if sink.Received() != sum {
			t.Fatal("Received diverge do original")
		}
		out, _ := os.ReadFile(filepath.Join(dst, "arq.bin"))
		if !bytes.Equal(out, data) {
			t.Fatalf("%d bytes: conteúdo diferente", size)
		}
		if names := dirNames(t, dst); len(names) != 1 {
			t.Fatalf("sobras no destino: %v", names)
		}
	}
}

func TestSinkHashMismatchLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	c := openCat(t, dir)
	data := []byte("conteúdo")
	wrong := sha256.Sum256([]byte("outro"))
	s, err := c.NewSink("x", int64(len(data)), wrong)
	if err != nil {
		t.Fatal(err)
	}
	s.Write(data)
	err = s.Commit()
	e, ok := IsHashMismatch(err)
	if !ok || e.Want != wrong || e.Got != sha256.Sum256(data) {
		t.Fatalf("esperado HashMismatchError, obtido %v", err)
	}
	if names := dirNames(t, dir); len(names) != 0 {
		t.Fatalf("arquivos restantes: %v", names)
	}
	s.Abort() // após Commit não faz nada
}

func TestSinkSizeChecks(t *testing.T) {
	dir := t.TempDir()
	c := openCat(t, dir)
	s, _ := c.NewSink("x", 3, [32]byte{})
	if _, err := s.Write([]byte("abcd")); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("escrita além do tamanho: %v", err)
	}
	s.Write([]byte("ab"))
	if err := s.Commit(); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("arquivo incompleto: %v", err)
	}

	s2, _ := c.NewSink("y", 3, [32]byte{})
	s2.Abort()
	if names := dirNames(t, dir); len(names) != 0 {
		t.Fatalf("Abort deixou: %v", names)
	}
}

func TestSinkNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x"), []byte("velho"), 0o644)
	c := openCat(t, dir)
	if _, err := c.NewSink("x", 1, [32]byte{}); !errors.Is(err, ErrExists) {
		t.Fatalf("esperado ErrExists, obtido %v", err)
	}

	// Arquivo criado durante a transferência também não é sobrescrito.
	data := []byte("novo")
	s, err := c.NewSink("y", int64(len(data)), sha256.Sum256(data))
	if err != nil {
		t.Fatal(err)
	}
	s.Write(data)
	os.WriteFile(filepath.Join(dir, "y"), []byte("concorrente"), 0o644)
	if err := s.Commit(); !errors.Is(err, ErrExists) {
		t.Fatalf("esperado ErrExists no Commit, obtido %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "y")); string(b) != "concorrente" {
		t.Fatal("arquivo existente foi sobrescrito")
	}
}

func TestUnmarshalMetaRejects(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	bad := []string{
		``, `{`, `[]`,
		`{"name":"../x","size":1,"block_size":1156,"sha256":"` + hex64 + `"}`,
		`{"name":"x","size":-1,"block_size":1156,"sha256":"` + hex64 + `"}`,
		`{"name":"x","size":1,"block_size":1000,"sha256":"` + hex64 + `"}`,
		`{"name":"x","size":1,"block_size":1156,"sha256":"abc"}`,
		`{"name":"x","size":1,"block_size":1156,"sha256":"` + strings.Repeat("zz", 32) + `"}`,
	}
	for _, p := range bad {
		if _, err := UnmarshalMeta([]byte(p)); !errors.Is(err, ErrBadMeta) {
			t.Errorf("%s aceito (err=%v)", p, err)
		}
	}
	// O maior nome permitido ainda cabe em um datagrama.
	for _, name := range []string{strings.Repeat("é", MaxNameLen/2), strings.Repeat("<", MaxNameLen),
		strings.Repeat(`"`, MaxNameLen)} {
		m := NewMeta(name, MaxFileSize, [32]byte{})
		b, err := m.Marshal()
		if err != nil {
			t.Fatalf("META máximo: %v", err)
		}
		if got, err := UnmarshalMeta(b); err != nil || got != m {
			t.Fatalf("round-trip de %q: %v", name[:3], err)
		}
	}
}
