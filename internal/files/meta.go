package files

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/wire"
)

// ErrBadMeta indica payload de META malformado ou com valores inválidos.
var ErrBadMeta = errors.New("files: META inválido")

// Meta é o conteúdo do payload de META (docs/protocolo.md, seção 4).
type Meta struct {
	Name      string
	Size      int64
	BlockSize int
	SHA256    [sha256.Size]byte
}

type metaJSON struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	BlockSize int    `json:"block_size"`
	SHA256    string `json:"sha256"`
}

// NewMeta monta o META de um arquivo com o tamanho de bloco padrão.
func NewMeta(name string, size int64, sum [sha256.Size]byte) Meta {
	return Meta{Name: name, Size: size, BlockSize: BlockSize, SHA256: sum}
}

// Validate confere nome, tamanho e tamanho de bloco.
func (m Meta) Validate() error {
	if err := ValidateName(m.Name); err != nil {
		return fmt.Errorf("%w: %w", ErrBadMeta, err)
	}
	if m.Size < 0 || m.Size > MaxFileSize {
		return fmt.Errorf("%w: %w: %d bytes", ErrBadMeta, ErrTooLarge, m.Size)
	}
	if m.BlockSize != BlockSize {
		return fmt.Errorf("%w: block_size %d (esperado %d)", ErrBadMeta, m.BlockSize, BlockSize)
	}
	return nil
}

// Blocks retorna o número de blocos do arquivo descrito.
func (m Meta) Blocks() uint32 { return NumBlocks(m.Size) }

// Marshal codifica o META em JSON, garantindo que caiba em um datagrama.
func (m Meta) Marshal() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	// Sem escape de <, > e &: com escape, um nome de 255 bytes poderia virar
	// mais de 1.156 bytes de JSON.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(metaJSON{
		Name: m.Name, Size: m.Size, BlockSize: m.BlockSize,
		SHA256: hex.EncodeToString(m.SHA256[:]),
	}); err != nil {
		return nil, err
	}
	b := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(b) > wire.MaxPayload {
		return nil, fmt.Errorf("%w: %d bytes não cabem no payload", ErrBadMeta, len(b))
	}
	return b, nil
}

// UnmarshalMeta decodifica e valida o payload de META.
func UnmarshalMeta(p []byte) (Meta, error) {
	var j metaJSON
	if err := json.Unmarshal(p, &j); err != nil {
		return Meta{}, fmt.Errorf("%w: %w", ErrBadMeta, err)
	}
	m := Meta{Name: j.Name, Size: j.Size, BlockSize: j.BlockSize}
	sum, err := hex.DecodeString(j.SHA256)
	if err != nil || len(sum) != sha256.Size {
		return Meta{}, fmt.Errorf("%w: sha256 %q", ErrBadMeta, j.SHA256)
	}
	copy(m.SHA256[:], sum)
	if err := m.Validate(); err != nil {
		return Meta{}, err
	}
	return m, nil
}
