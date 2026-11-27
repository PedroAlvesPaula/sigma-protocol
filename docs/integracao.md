# Integração transporte ↔ aplicação

**Para:** Pedro (transporte, membro 1). **De:** Lucas (aplicação, membro 2).
**Objetivo:** combinar a fronteira entre `internal/transport` (Selective Repeat)
e o cliente/servidor, para que a troca do stub pelo transporte real seja só
mudar uma chamada.

Resumo: **o transporte só move bytes** de um `io.ReaderAt` para um
`io.Writer`, de DATA até FIN_ACK. Nome do arquivo, tamanho, SHA-256, META,
autenticação e escolha do Transfer ID ficam na aplicação. Isso muda um pouco
o `passos.md` (passo 6 colocava META e SHA-256 no transporte), ver §4.

## 1. O que já existe do meu lado

| Pacote | O que faz |
| ------ | --------- |
| `internal/files` | catálogo do diretório (confinado com `os.Root`), blocos (`NumBlocks`, `BlockRange`), SHA-256, `Sink` (temporário + hash + rename) e META |
| `internal/proto` | payloads JSON de controle, códigos de ERROR, `RemoteError`, `CodeFor(err)` |
| `internal/auth` | HMAC-SHA256 desafio/resposta, geração de IDs |
| `internal/control` | requisição/resposta com retransmissão (`Call`) |
| `internal/xfer` | **stub stop-and-wait** com a assinatura abaixo — é ele que você substitui |
| `internal/server` | servidor (um socket, várias sessões e transferências) |
| `internal/client` | cliente (login, list, get, put) |
| `internal/discovery` | mini-CDN (PING/PONG, RTT, escolha) |

Especificação das mensagens de controle: `docs/protocolo.md`, seção 9.
Fluxo completo da aplicação: `docs/aplicacao.md`.

## 2. Contrato pedido ao transporte

Hoje em `internal/xfer/xfer.go` (stub). A proposta é você implementar as
mesmas funções em `internal/transport` (ou dentro de `internal/xfer`, como
preferir):

```go
type IDs struct {
    Session  uint64 // Header.SessionID de todos os datagramas
    Transfer uint64 // Header.TransferID de todos os datagramas
}

type Config struct {
    Window     int           // janela local em blocos (-window na CLI)
    RTO        time.Duration // no stub é fixo; no seu, o RTO inicial
    MaxRetries int           // retransmissões do mesmo bloco antes de desistir
    Idle       time.Duration // tempo máximo sem datagrama válido do par
    Linger     time.Duration // receptor: tempo respondendo FIN repetido depois do FIN_ACK
}

type Stats struct {
    Blocks, ...              // ver internal/xfer — pode acrescentar campos à vontade
    Retransmissions uint64
    Duration        time.Duration
}

// Emissor: envia src[0:size) e retorna depois do FIN_ACK.
// ERROR do par → retorna *proto.RemoteError (ex.: HASH_MISMATCH).
func Send(ctx context.Context, conn transport.PacketConn, peer net.Addr, ids IDs,
    src io.ReaderAt, size int64, cfg Config) (Stats, error)

// Receptor: escreve os bytes EM ORDEM em dst. Ao receber FIN com tudo gravado,
// chama finalize(); se der erro, envia ERROR com proto.CodeFor(err) no lugar
// do FIN_ACK e retorna o erro; senão envia FIN_ACK.
func Receive(ctx context.Context, conn transport.PacketConn, peer net.Addr, ids IDs,
    dst io.Writer, size int64, cfg Config, finalize func() error) (Stats, error)
```

### Regras que a aplicação assume

1. **Bloco `i`** = bytes `files.BlockRange(i, size)` (1.156 bytes, o último
   menor). `N = files.NumBlocks(size)`. Arquivo vazio: `N = 0`, vai direto
   para FIN.
2. **Todos os datagramas** (DATA, ACK, FIN, FIN_ACK, ERROR) levam `ids.Session`
   e `ids.Transfer`. O transporte **ignora** datagramas com outros IDs: no
   cliente o socket é compartilhado com o controle, então podem chegar
   respostas atrasadas de LIST/GET etc.
3. **`dst.Write` só recebe o prefixo contíguo**, em ordem (é o `files.Sink`,
   que calcula o SHA-256 enquanto grava). O buffer de reordenação é do
   transporte. `dst.Write` pode falhar (disco cheio, escrita além do
   tamanho): trate como fim da transferência com ERROR `proto.CodeFor(err)`.
4. **`finalize` roda antes do FIN_ACK.** É `sink.Commit`, que confere o
   SHA-256 e faz o rename. FIN_ACK significa "arquivo íntegro e publicado".
5. **Primeiro DATA pode se perder** de propósito: no GET, o servidor começa a
   enviar logo depois do META, e se o META se perder o cliente ainda não
   está ouvindo a transferência. A retransmissão por timeout resolve; só não
   pode desistir cedo demais (com `MaxRetries` = 10 e backoff está ok).
6. **Janela inicial:** no PUT o META_ACK traz `Receive Window` = janela do
   servidor, mas o emissor não recebe esse valor (é o cliente quem lê o
   META_ACK). Sugestão: começar com `cfg.Window` e ajustar pelo `Window` de
   cada ACK, como já previsto. Se quiser receber a janela inicial, acrescente
   um campo em `Config` (`PeerWindow`) e eu passo.
7. **`conn.SetReadDeadline`** funciona (inclusive na conexão virtual do
   servidor), mas lá só vale para a próxima leitura: defina o prazo antes de
   cada `ReadFrom`, como o stub faz. Restaure `time.Time{}` ao sair.
8. **Nada de `Close` no `conn`**: ele pertence a quem chamou.
9. Erros: devolva `ctx.Err()` em cancelamento; para timeout um erro que eu
   consiga reconhecer (hoje `xfer.ErrTimeout`; pode ser um seu, me avisa o nome).

### Servidor: uma conexão virtual por transferência

O servidor tem um único socket. `internal/server/vconn.go` entrega a cada
transferência um `transport.PacketConn` que só lê os datagramas daquela
`(Session ID, Transfer ID)` e escreve direto no socket. Então o seu
`Send/Receive` funciona igual no cliente (socket real), no servidor (vconn) e
nos testes (`Pipe` + `LossyConn`). **Não precisa** fazer demultiplexação.

## 3. Como trocar o stub (quando o SR estiver pronto)

Só duas linhas em cada lado chamam o transporte:

| Arquivo | Chamada |
| ------- | ------- |
| `internal/server/handlers.go` (`doGet`) | `xfer.Send(ctx, vc, addr, ids, f, size, s.cfg.Xfer)` |
| `internal/server/handlers.go` (`doPut`) | `xfer.Receive(ctx, vc, addr, ids, sink, meta.Size, s.cfg.Xfer, sink.Commit)` |
| `internal/client/client.go` (`Get`) | `xfer.Receive(...)` |
| `internal/client/client.go` (`Put`) | `xfer.Send(...)` |

Opção mais simples: manter o pacote `xfer` e fazer `xfer.Send/Receive`
chamarem o seu código (ou mover seu código para lá). Os testes
`internal/server/e2e_test.go` (5% de perda, duplicação, corrupção e
reordenação via `LossyConn`) devem continuar passando sem mudança: são o
critério de "integrou".

## 4. Diferenças em relação ao `passos.md`

| `passos.md` | Combinado aqui | Por quê |
| ----------- | -------------- | ------- |
| Passo 6: emissor envia META e espera META_ACK dentro do transporte | META/META_ACK são resposta de GET/PUT (controle, com retransmissão e idempotência da aplicação) | Quem sabe nome/tamanho/hash é a aplicação; evita duas negociações |
| Passo 6: receptor compara o SHA-256 | Receptor chama `finalize` (= `files.Sink.Commit`) antes do FIN_ACK | Mesmo comportamento, mas o hash fica em `internal/files` |
| Passo 8: subcomando provisório send/recv | Já existem `sigma-client list/get/put/probe` e `sigma-server` | Use-os para testar o SR com UDP real |

O resto (Selective Repeat, buffer de reordenação, RTO adaptativo, Karn, janela
anunciada, sonda de janela zero, métricas) continua 100% seu, como no `passos.md`.

## 5. Desempenho: por que a integração é urgente

O stub é stop-and-wait (1 bloco por RTT). Medido em loopback: 80 MiB em 11 s
(61 Mbit/s, RTT ≈ 0,1 ms). Nos cenários do enunciado o teto é
`1156 B · 8 / RTT`:

| RTT | Teto stop-and-wait | 80 MiB levaria |
| --- | ------------------ | -------------- |
| 25 ms | 0,37 Mbit/s | ~30 min |
| 100 ms | 0,09 Mbit/s | ~2 h |
| 400 ms | 0,02 Mbit/s | ~8 h |

Ou seja: os experimentos do Emerson dependem do SR.

## 6. Ambiente: `shellHook` do `flake.nix`

O `shellHook` faz `exec $SHELL` (zsh). No terminal interativo funciona, mas
`nix develop -c go test ./...` **não roda o comando** (o `exec` substitui o
shell antes). Sugestão: tirar o `exec` do `shellHook` e, para quem quer zsh,
entrar com `nix develop path:. -c zsh` (ou usar direnv). Assim
`nix develop path:. -c go test ./...` volta a funcionar, o que também serve
para scripts de experimento do Emerson. Enquanto isso:
`nix print-dev-env path:. | grep -v 'exec $SHELL' > /tmp/env.sh; source /tmp/env.sh`.

## 7. Pontos para você confirmar

- [ ] Assinaturas de `Send`/`Receive` e o significado de `finalize`.
- [ ] Onde o código vai morar (`internal/transport` chamado por `xfer`, ou direto em `xfer`).
- [ ] Nome do erro de timeout que a aplicação deve reconhecer.
- [ ] Se quer `PeerWindow` em `Config` (regra 6).
- [ ] Campos de `Stats` que você vai expor (o cliente grava em CSV via `-csv`; o Emerson precisa de retransmissões e RTT).
