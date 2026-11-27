// Package files implementa a parte de arquivos do Sigma Protocol: catálogo
// confinado a um diretório, divisão em blocos, SHA-256 e gravação segura
// (temporário + validação de hash + rename).
//
// O transporte (internal/transport) só move bytes entre um io.ReaderAt e um
// io.Writer; nome, tamanho e hash do arquivo são responsabilidade deste pacote.
package files

import "github.com/PedroAlvesPaula/sigma-protocol/internal/wire"

// BlockSize é o tamanho de um bloco de dados: o payload máximo de um DATA.
const BlockSize = wire.MaxPayload

// MaxFileSize é o maior arquivo transferível sem que o Sequence (uint32) dê
// a volta: (2^32 − 1) blocos.
const MaxFileSize int64 = (1<<32 - 1) * BlockSize

// NumBlocks retorna ceil(size / BlockSize). Arquivo vazio tem 0 blocos.
func NumBlocks(size int64) uint32 {
	if size <= 0 {
		return 0
	}
	return uint32((size + BlockSize - 1) / BlockSize)
}

// BlockRange retorna o deslocamento e o tamanho do bloco i de um arquivo com
// size bytes. Para i fora do arquivo, n é 0.
func BlockRange(i uint32, size int64) (off int64, n int) {
	off = int64(i) * BlockSize
	if off >= size {
		return off, 0
	}
	return off, int(min(BlockSize, size-off))
}
