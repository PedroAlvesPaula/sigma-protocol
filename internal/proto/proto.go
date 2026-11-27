// Package proto define os payloads JSON das mensagens de controle do Sigma
// Protocol (autenticação, LIST, GET, PUT, ERROR, PING/PONG) e os códigos de
// erro trocados entre cliente e servidor. A especificação está em
// docs/protocolo.md, seção 9.
//
// O pacote não faz E/S: só codifica e decodifica payloads. É importado pelo
// cliente, pelo servidor e pela camada de transferência.
package proto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/PedroAlvesPaula/sigma-protocol/internal/files"
	"github.com/PedroAlvesPaula/sigma-protocol/internal/wire"
)

// Códigos de erro do payload de ERROR.
const (
	CodeHashMismatch     = "HASH_MISMATCH"     // SHA-256 recebido difere do original
	CodeTimeout          = "TIMEOUT"           // par parou de responder
	CodeBadRequest       = "BAD_REQUEST"       // payload malformado ou nome inválido
	CodeNotFound         = "NOT_FOUND"         // arquivo inexistente
	CodeNoSpace          = "NO_SPACE"          // falta de espaço em disco
	CodeInternal         = "INTERNAL"          // falha inesperada
	CodeAuthFailed       = "AUTH_FAILED"       // senha incorreta
	CodeNotAuthenticated = "NOT_AUTHENTICATED" // sessão inexistente ou não autenticada
	CodeExists           = "EXISTS"            // upload de nome que já existe
	CodeTooLarge         = "TOO_LARGE"         // arquivo maior que o máximo
	CodeBusy             = "BUSY"              // limite de sessões/transferências
)

// ErrBadPayload indica JSON malformado ou grande demais para um datagrama.
var ErrBadPayload = errors.New("proto: payload inválido")

// RemoteError é um ERROR recebido do par.
type RemoteError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("erro remoto %s: %s", e.Code, e.Message)
}

// IsCode informa se err é um *RemoteError com o código dado.
func IsCode(err error, code string) bool {
	var re *RemoteError
	return errors.As(err, &re) && re.Code == code
}

// Challenge é o payload de CHALLENGE (servidor → cliente).
type Challenge struct {
	Nonce string `json:"nonce"` // 32 bytes em hexadecimal
}

// Auth é o payload de AUTH (cliente → servidor).
type Auth struct {
	MAC string `json:"mac"` // HMAC-SHA256 em hexadecimal (ver internal/auth)
}

// ListReq é o payload de LIST. Offset é o índice do primeiro arquivo da
// página pedida (0 na primeira).
type ListReq struct {
	Offset int `json:"offset"`
}

// ListResult é o payload de LIST_RESULT. Next é o Offset da próxima página,
// ou -1 se esta for a última.
type ListResult struct {
	Files []files.Entry `json:"files"`
	Next  int           `json:"next"`
}

// GetReq é o payload de GET.
type GetReq struct {
	Name string `json:"name"`
}

// Ping é o payload de PING e de PONG (o PONG ecoa o nonce).
type Ping struct {
	Nonce string `json:"nonce"`
}

// Marshal codifica v em JSON sem escapar <, > e & (para que nomes de arquivo
// não cresçam) e garante que o resultado caiba em um datagrama.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadPayload, err)
	}
	b := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(b) > wire.MaxPayload {
		return nil, fmt.Errorf("%w: %d bytes (máximo %d)", ErrBadPayload, len(b), wire.MaxPayload)
	}
	return b, nil
}

// Unmarshal decodifica o payload p em v.
func Unmarshal(p []byte, v any) error {
	if err := json.Unmarshal(p, v); err != nil {
		return fmt.Errorf("%w: %w", ErrBadPayload, err)
	}
	return nil
}

// ErrorPayload monta o payload de ERROR. Mensagens longas são truncadas para
// caber no datagrama.
func ErrorPayload(code, message string) []byte {
	const maxMsg = 900
	if len(message) > maxMsg {
		message = message[:maxMsg] + "…"
	}
	b, err := Marshal(RemoteError{Code: code, Message: message})
	if err != nil { // só ocorre com código absurdo; nunca com os definidos aqui
		b, _ = Marshal(RemoteError{Code: CodeInternal, Message: "erro"})
	}
	return b
}

// ParseError decodifica o payload de um ERROR recebido. Nunca retorna nil:
// um payload malformado vira um RemoteError com código INTERNAL.
func ParseError(p []byte) *RemoteError {
	var e RemoteError
	if err := json.Unmarshal(p, &e); err != nil || e.Code == "" {
		return &RemoteError{Code: CodeInternal, Message: fmt.Sprintf("ERROR malformado: %q", p)}
	}
	return &e
}

// CodeFor traduz um erro local no código de ERROR enviado ao par.
func CodeFor(err error) string {
	var re *RemoteError
	switch {
	case errors.As(err, &re):
		return re.Code
	case errors.Is(err, files.ErrNotFound):
		return CodeNotFound
	case errors.Is(err, files.ErrExists):
		return CodeExists
	case errors.Is(err, files.ErrTooLarge):
		return CodeTooLarge
	case errors.Is(err, files.ErrInvalidName), errors.Is(err, files.ErrBadMeta),
		errors.Is(err, ErrBadPayload):
		return CodeBadRequest
	case errors.Is(err, files.ErrSizeMismatch):
		return CodeBadRequest
	}
	if _, ok := files.IsHashMismatch(err); ok {
		return CodeHashMismatch
	}
	if isNoSpace(err) {
		return CodeNoSpace
	}
	return CodeInternal
}
