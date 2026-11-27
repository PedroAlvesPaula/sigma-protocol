// Package auth implementa a autenticação por senha do Sigma Protocol
// (desafio/resposta com HMAC-SHA256), descrita em docs/protocolo.md, seção 9.2.
//
// A senha nunca trafega: o servidor envia um nonce aleatório de uso único e
// o cliente responde com HMAC-SHA256(chave, SessionID || nonce), onde
// chave = SHA-256(senha). O servidor recalcula e compara em tempo constante.
//
// Limitações (documentadas no relatório): não há confidencialidade, o
// servidor não é autenticado e quem captura um desafio e sua resposta pode
// tentar adivinhar senhas fracas offline.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// NonceLen é o tamanho do desafio em bytes.
const NonceLen = 32

// Key deriva a chave de HMAC a partir da senha.
func Key(password string) [sha256.Size]byte {
	return sha256.Sum256([]byte(password))
}

// NewNonce gera um desafio aleatório.
func NewNonce() []byte {
	n := make([]byte, NonceLen)
	rand.Read(n)
	return n
}

// NewID gera um identificador aleatório não nulo (Session ID, Transfer ID).
func NewID() uint64 {
	for {
		var b [8]byte
		rand.Read(b[:])
		if id := binary.BigEndian.Uint64(b[:]); id != 0 {
			return id
		}
	}
}

// MAC calcula a resposta ao desafio: HMAC-SHA256(key, SessionID || nonce),
// com o SessionID em big-endian.
func MAC(key [sha256.Size]byte, session uint64, nonce []byte) []byte {
	m := hmac.New(sha256.New, key[:])
	var sid [8]byte
	binary.BigEndian.PutUint64(sid[:], session)
	m.Write(sid[:])
	m.Write(nonce)
	return m.Sum(nil)
}

// Verify confere uma resposta recebida em hexadecimal, em tempo constante.
func Verify(key [sha256.Size]byte, session uint64, nonce []byte, macHex string) bool {
	got, err := hex.DecodeString(macHex)
	if err != nil {
		return false
	}
	return hmac.Equal(got, MAC(key, session, nonce))
}
