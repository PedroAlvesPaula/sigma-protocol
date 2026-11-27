package auth

import (
	"encoding/hex"
	"testing"
)

func TestVerify(t *testing.T) {
	key := Key("segredo")
	nonce := NewNonce()
	mac := hex.EncodeToString(MAC(key, 42, nonce))

	if !Verify(key, 42, nonce, mac) {
		t.Fatal("resposta correta recusada")
	}
	if Verify(Key("outra"), 42, nonce, mac) {
		t.Fatal("senha errada aceita")
	}
	if Verify(key, 43, nonce, mac) {
		t.Fatal("resposta aceita em outra sessão")
	}
	if Verify(key, 42, NewNonce(), mac) {
		t.Fatal("resposta aceita para outro desafio (replay)")
	}
	if Verify(key, 42, nonce, "zz") {
		t.Fatal("hex inválido aceito")
	}
	if NewID() == 0 {
		t.Fatal("ID zero")
	}
}
