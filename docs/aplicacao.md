# Aplicação, arquivos, autenticação e mini-CDN (membro 2)

Este documento explica **como a aplicação funciona de ponta a ponta**: o que
acontece desde `sigma-client get teste.bin` até o arquivo aparecer no disco com
o hash conferido. É escrito para quem vai apresentar e responder perguntas
sobre esta parte.

Documentos relacionados:

- `docs/protocolo.md` — formato binário (cabeçalho) e, na seção 9, as
  mensagens de controle.
- `docs/integracao.md` — contrato com o transporte (Pedro).
- `docs/passos.md` — transporte Selective Repeat (Pedro).

## 1. Mapa dos pacotes

```text
cmd/sigma-client ──► internal/discovery   (mini-CDN: PING/PONG, RTT, escolha)
        │
        └──────────► internal/client ──┬─► internal/control  (requisição/resposta com retransmissão)
                                       ├─► internal/auth     (HMAC desafio/resposta)
                                       ├─► internal/files    (Sink, META, SHA-256)
                                       └─► internal/xfer     (transferência DATA/ACK/FIN)

cmd/sigma-server ──► internal/server ──┬─► internal/files    (Catalog, Sink, META, SHA-256)
                                       ├─► internal/auth
                                       └─► internal/xfer  (via vconn: um "socket" por transferência)

Todos usam: internal/wire (cabeçalho, Encode/Decode) e internal/proto (payloads JSON, códigos de erro)
Testes usam: internal/transport (Pipe em memória, LossyConn com perdas)
```

Camadas, de baixo para cima:

| Camada | Pacote | Responsabilidade | Dono |
| ------ | ------ | ---------------- | ---- |
| Datagrama | `wire` | 44 bytes de cabeçalho, CRC32C, validação | Pedro |
| Rede simulada | `transport` (conn, lossy) | `PacketConn`, `Pipe`, `LossyConn` | Pedro |
| Transferência | `xfer` → `transport` (SR) | mover bytes de forma confiável e em ordem | stub: Lucas; real: Pedro |
| Controle | `control`, `proto`, `auth` | pedir/responder, autenticar, erros | Lucas |
| Arquivos | `files` | ler em blocos, hash, gravar com segurança | Lucas |
| Aplicação | `server`, `client`, `discovery`, `cmd/*` | sessões, LIST/GET/PUT, mini-CDN, CLI | Lucas |

Ideia central: **cada camada não sabe das de cima.** O transporte não sabe o
que é um arquivo; `files` não sabe o que é rede; o cliente não sabe como a
janela funciona.

## 2. Uso rápido

```sh
# dentro de `nix develop path:.`
go build -o bin/ ./cmd/...
mkdir -p shared && head -c 83886080 /dev/urandom > shared/teste.bin   # 80 MiB

export SIGMA_PASSWORD=segredo
bin/sigma-server -bind 127.0.0.1:9000 -dir shared &
bin/sigma-server -bind 127.0.0.1:9001 -dir shared -sim-delay 20ms &    # "servidor longe"

C="bin/sigma-client -servers 127.0.0.1:9000,127.0.0.1:9001"
$C probe                     # só mede RTT e mostra a escolha
$C list
$C -o downloads get teste.bin
$C put algum-arquivo.bin
$C -server 127.0.0.1:9001 get teste.bin    # força servidor (comparação manual)
$C -csv metricas.csv get teste.bin         # grava métricas para os gráficos
```

Flags importantes:

| Flag | Onde | Para quê |
| ---- | ---- | -------- |
| `-servers a,b` | cliente | lista da mini-CDN; com 2+ servidores mede RTT e escolhe |
| `-server a` | cliente | força um servidor (pula a medição) |
| `-window N`, `-rto D` | ambos | parâmetros do transporte |
| `-csv arq` | cliente | acrescenta uma linha de métricas por transferência |
| `-sim-loss p`, `-sim-delay d` | ambos | perda/atraso simulados na aplicação (`LossyConn`), para testar sem `tc netem` |
| `-v` | servidor | log detalhado |

A senha vem de `SIGMA_PASSWORD` (no cliente, se vazia, é pedida no
terminal). Não é flag para não aparecer em `ps` nem no histórico.

## 3. Uma operação completa: `get teste.bin`

Passo a passo do que acontece, com o arquivo/função de cada etapa.

### 3.1 Escolha do servidor (mini-CDN)

`cmd/sigma-client/main.go: chooseServer` → `internal/discovery: Probe, Choose`

1. O cliente abre **um** socket UDP numa porta efêmera (`net.ListenUDP`).
2. Em cada uma de 5 rodadas, envia um PING a cada servidor. Cada PING tem um
   `Seq` único e um nonce aleatório no payload; o instante de envio fica
   guardado em `waiting[seq]`.
3. Lê respostas até todos da rodada responderem ou passar 1 s. Um PONG só é
   aceito se: (a) `Ack` é um `Seq` pendente, (b) veio do endereço para o qual
   aquele PING foi, (c) o nonce bate. RTT = `agora − envio` (relógio
   monotônico do Go, imune a ajuste de hora).
4. PONG atrasado de rodada anterior ainda conta: o RTT é medido a partir do
   envio do próprio PING.
5. `Choose`: entre os servidores com pelo menos 3 respostas, o de **menor
   mediana**. Empate → o primeiro da lista. Nenhum elegível → erro.

**Por que mediana e não média?** Um único PING atrasado (fila momentânea,
escalonamento do SO) puxaria a média; a mediana ignora outliers.

**Por que PING não exige autenticação?** A escolha vem antes de saber em
qual servidor autenticar; PING não revela nada nem altera estado.

### 3.2 Autenticação

`internal/client: Login` ↔ `internal/server: handleHello, doAuth` + `internal/auth`

```text
Cliente                                   Servidor
HELLO  (Session=0, Seq=1)          ──►    cria sessão: ID aleatório 64 bits + nonce 32 bytes
       ◄──  CHALLENGE (Session=S, Ack=1, {"nonce": ...})
AUTH   (Session=S, Seq=2, {"mac": HMAC(SHA256(senha), S||nonce)})  ──►
                                          recalcula o HMAC e compara com hmac.Equal
       ◄──  AUTH_OK (Ack=2)   ou   ERROR AUTH_FAILED
```

- A senha nunca trafega; só um HMAC que depende do nonce sorteado pelo
  servidor. Capturar um AUTH não ajuda a entrar em outra sessão (outro nonce).
- `hmac.Equal` compara em tempo constante (não vaza quantos bytes acertou).
- Depois de uma falha o nonce é apagado: não dá para tentar várias senhas na
  mesma sessão.
- A sessão fica presa ao endereço IP:porta do cliente; datagramas da sessão
  vindos de outro endereço são ignorados.
- Limitações honestas (para o relatório): sem criptografia, servidor não é
  autenticado, senha fraca pode ser quebrada offline por quem capturou
  CHALLENGE + AUTH.

### 3.3 Requisição/resposta confiável (vale para tudo acima e abaixo)

`internal/control: Call` e `internal/server: handleRequest`

Mensagens de controle também podem se perder. A regra:

1. O cliente numera cada requisição (`Seq` = 1, 2, 3...).
2. Envia e espera uma resposta com `Ack == Seq` (e da mesma sessão). Se não
   chegar em 500 ms, reenvia; o timeout dobra até 4 s; 6 tentativas (≈15 s)
   e desiste com "servidor não responde".
3. O servidor guarda, por sessão, o último `Seq` e a resposta enviada. Se
   chegar o mesmo `Seq` de novo (a resposta se perdeu), **reenvia a resposta
   guardada sem executar de novo**. Isso é idempotência: um GET retransmitido
   não abre uma segunda transferência; um PUT retransmitido não cria outro
   temporário.
4. `Seq` menor que o último: requisição velha atrasada, ignorada.

### 3.4 LIST

`client.List` → `server.doList` → `server.ListPage`

Um datagrama tem no máximo 1.156 bytes de payload, então a lista é
**paginada**: o cliente pede `{"offset": 0}`; o servidor coloca o máximo de
entradas que cabe e devolve `next` (próximo offset) ou `-1`. O cliente repete
até `-1`. Só aparecem arquivos regulares, visíveis e com nome válido.

### 3.5 GET: negociação

`client.Get` → `server.doGet`

1. Cliente envia `GET {"name": "teste.bin"}`.
2. Servidor: `Catalog.Open` (valida o nome e abre dentro do diretório),
   `Catalog.Hash` (SHA-256, em cache), monta o META
   `{"name","size","block_size":1156,"sha256"}`, sorteia um **Transfer ID** e
   registra a transferência com uma `vconn` (3.7).
3. Responde META (com o Transfer ID no cabeçalho) e só então inicia a
   goroutine que envia o arquivo (`xfer.Send`).
4. Cliente valida o META (nome igual ao pedido, tamanho e bloco coerentes) e
   cria um `Sink` (3.6) no diretório de destino.
5. Cliente chama `xfer.Receive(..., sink, size, ..., sink.Commit)`.

Se o META se perder: o cliente reenvia GET (mesmo `Seq`), recebe o mesmo
META. Os DATA que chegaram antes do META são descartados pelo cliente e o
emissor os reenvia por timeout.

### 3.6 Gravação segura e SHA-256 (`files.Sink`)

`internal/files/sink.go`

```text
NewSink ─► cria ".sigma-tmp-<aleatório>" no diretório (O_EXCL)
Write   ─► grava no temporário (bufio) E alimenta sha256 ao mesmo tempo
            (rejeita escrever além do tamanho do META)
Commit  ─► 1. bytes gravados == tamanho?          senão ErrSizeMismatch
           2. sha256(recebido) == sha256(META)?   senão HashMismatchError{Want, Got}
           3. flush + fsync + close
           4. o nome final ainda não existe?       senão ErrExists
           5. rename(temporário → nome final)     (atômico)
           Em qualquer falha: apaga o temporário.
Abort   ─► apaga o temporário (chamado quando a transferência falha)
```

Consequências que valem destacar:

- **Nunca existe arquivo final corrompido ou pela metade**: ou o arquivo
  aparece completo e com hash certo, ou não aparece.
- O hash é calculado **durante** a escrita (não relê 80 MB no fim).
- Upload nunca sobrescreve arquivo existente (checado no início e no rename).
- Temporários começam com ponto, então não aparecem no LIST nem podem ser
  pedidos por GET.

**CRC32C vs SHA-256:** o CRC32C (no cabeçalho, de cada datagrama) detecta
corrupção acidental de um pacote e faz o receptor descartá-lo. O SHA-256
cobre o arquivo inteiro e detecta qualquer erro que tenha escapado: bloco
fora de ordem, bug no transporte, arquivo alterado no servidor, etc. É o
"hash original × hash recebido" que o enunciado pede no relatório.

### 3.7 Transferência e a conexão virtual do servidor

`internal/xfer` (stub; vai ser o SR do Pedro) e `internal/server/vconn.go`

- O transporte recebe um `PacketConn`, um par de IDs, a origem (`io.ReaderAt`,
  o próprio `*os.File`) ou o destino (`io.Writer`, o `Sink`), e o tamanho.
- No **cliente**, o `PacketConn` é o socket UDP real.
- No **servidor** há um socket só para todos os clientes. O laço principal
  (`Server.Serve`) lê o socket e encaminha cada DATA/ACK/FIN/FIN_ACK/ERROR para
  a fila da transferência certa, pela chave `(Session ID, Transfer ID)` e
  conferindo o endereço. Cada transferência enxerga uma `vconn`: um
  `PacketConn` que só lê a própria fila e escreve no socket comum. Assim o
  transporte é idêntico nos dois lados e nos testes.
- Fim: o emissor envia FIN; o receptor, com tudo gravado, chama
  `finalize` = `sink.Commit`. Hash certo → FIN_ACK; errado → ERROR
  `HASH_MISMATCH`. O emissor só considera sucesso ao receber FIN_ACK.
- FIN_ACK perdido: o receptor continua respondendo FIN repetido por um tempo
  (linger) e, no servidor, a resposta final fica guardada 10 s.

### 3.8 PUT (o mesmo, com os papéis trocados)

`client.Put` → `server.doPut`

1. Cliente abre o arquivo, calcula o SHA-256 e envia `PUT` com o META.
2. Servidor valida o META, cria o `Sink` (recusa `EXISTS`), sorteia Transfer
   ID, responde `META_ACK` (com sua janela) e inicia `xfer.Receive` com
   `finalize = sink.Commit`.
3. Cliente chama `xfer.Send`. FIN_ACK significa que o **servidor** conferiu o
   hash e publicou o arquivo.

### 3.9 Saída

O cliente imprime nome, tamanho, blocos, **sha256 original e recebido**,
duração, goodput (Mbit/s), contadores (DATA, retransmissões, duplicatas,
corrompidos) e "integridade: OK". Com `-csv` grava a mesma informação numa
linha (colunas em `cmd/sigma-client/main.go: csvHeader`). O servidor registra
o hash original de todos os arquivos ao subir e o recebido em cada upload.

## 4. O laço do servidor

`internal/server/server.go: Serve, handle`

```text
loop:
  lê datagrama (prazo de 1 s para checar Ctrl+C e limpar sessões)
  wire.Decode  → inválido (CRC, tamanho, versão...)? descarta
  tipo:
    DATA, ACK, FIN, FIN_ACK, ERROR → route: fila da transferência (vconn)
    PING                           → PONG na hora
    HELLO                          → nova sessão + CHALLENGE
    AUTH, LIST, GET, PUT           → handleRequest (idempotência, autenticação, doX)
    outros                         → ignora (são tipos que só o servidor envia)
```

- Os handlers de controle rodam no próprio laço e são rápidos (nunca esperam
  a rede). O único trabalho pesado, o SHA-256 dos arquivos, é feito ao subir
  (`WarmHashes`) e fica em cache.
- Cada transferência roda numa goroutine própria; o estado compartilhado
  (sessões, transferências) é protegido por um mutex (`Server.mu`).
- Limites: 64 sessões, 16 transferências simultâneas (ERROR `BUSY`), sessão
  expira após 2 min sem tráfego (se não tiver transferência ativa).
- Ctrl+C: cancela o contexto, as transferências param e o servidor espera
  todas terminarem.

## 5. Segurança de arquivos (`files.Catalog`)

- Todo acesso passa por `os.Root` (Go 1.24+): o SO garante que nenhum
  caminho, nem por link simbólico, sai do diretório compartilhado.
- Além disso, `ValidateName` só aceita **um nome simples**: sem `/` ou `\`,
  sem `..`, sem ponto inicial, sem caracteres de controle, UTF-8 válido,
  ≤ 255 bytes.
- `GET ../etc/passwd` → `BAD_REQUEST`; link para fora → não abre.

## 6. Tratamento de erros (requisito da seção 3 do enunciado)

| Situação | Onde é detectada | O que o usuário vê |
| -------- | ---------------- | ------------------ |
| Datagrama corrompido | `wire.Decode` (CRC32C) | nada: descartado e retransmitido; contado em "corrompidos" |
| Resposta de controle perdida | `control.Call` (timeout) | nada: reenvia; após ~15 s "servidor não responde" |
| Servidor fora do ar na seleção | `discovery.Probe` | "indisponível" na tabela; escolhe o outro ou "nenhum servidor disponível" |
| Senha errada | `auth.Verify` → `AUTH_FAILED` | "senha incorreta" |
| Arquivo inexistente / nome inválido | `Catalog.Open` → `NOT_FOUND` / `BAD_REQUEST` | mensagem correspondente |
| Upload com nome existente | `NewSink`/`Commit` → `EXISTS` | "já existe um arquivo com esse nome" |
| Hash divergente (download) | `Sink.Commit` no cliente | os dois hashes; arquivo não é criado |
| Hash divergente (upload) | `Sink.Commit` no servidor → ERROR `HASH_MISMATCH` | mensagem com os dois hashes |
| Disco cheio | `Sink.Write` → `NO_SPACE` | mensagem; temporário apagado |
| Par sumiu no meio | transporte (timeout) | "servidor não responde" |

A tradução erro → código está em `proto.CodeFor`; código → frase em
`client.Describe`.

## 7. Mini-CDN: perguntas do relatório (seção 6 do enunciado)

- **Qual servidor foi escolhido?** O cliente imprime a tabela de RTTs e a
  linha "servidor escolhido". Para o relatório, use as duas máquinas reais e
  guarde essa saída junto com a captura do Wireshark (PING/PONG).
- **Qual o impacto no desempenho?** Compare `get` com seleção automática
  contra `-server` forçado em cada máquina, mesmo arquivo e janela, gravando
  com `-csv`. Com janela W, o goodput sem perdas é limitado por
  `W · 1156 B · 8 / RTT`: o servidor de menor RTT entrega mais.
- **Relação com CDNs:** CDNs mapeiam o cliente para um servidor "próximo"
  (DNS que responde IPs diferentes conforme a origem, anycast, medições de
  latência/carga). Aqui a medição é **ativa e feita pelo cliente** (sondagem
  direta), parecida com o que alguns clientes fazem para escolher réplicas.
  Diferenças: não há DNS nem anycast, não se considera a carga nem a
  capacidade do servidor, a medição custa ~5 RTTs antes de cada operação, e a
  replicação dos arquivos entre servidores é manual.

## 8. Testes

```sh
go test ./...                 # tudo
go test -race ./...           # com detector de corrida (ver README para cgo no nix)
go test -v ./internal/server  # cliente+servidor de ponta a ponta
```

| Teste | O que prova |
| ----- | ----------- |
| `files`: `TestSinkRoundTrip` | arquivos de 0, 1, 1.156, 1.157 B e 5 MB chegam idênticos |
| `files`: `TestSinkHashMismatchLeavesNothing`, `TestSinkNoOverwrite` | hash errado ou nome existente não deixam lixo nem sobrescrevem |
| `files`: `TestCatalogSymlinkEscape`, `TestValidateName` | não sai do diretório |
| `server`: `TestFullFlow/com falhas` | login, LIST, GET, PUT e erros com **5% de perda nos dois sentidos, duplicação, corrupção e reordenação** |
| `server`: `TestWrongPassword`, `TestGetHashMismatch` | senha errada; arquivo alterado no servidor é recusado pelo cliente |
| `discovery`: `TestChoosesFastest`, `TestUnavailableServer` | escolhe o de menor RTT (servidores UDP reais, um com +30 ms); ignora o que não responde |
| `auth`: `TestVerify` | senha errada, outra sessão e replay de outro desafio são recusados |

Validação manual feita em loopback (27/11/2026): dois servidores (um com
`-sim-delay 20ms`), seleção escolheu o de 0,17 ms contra 20,5 ms; GET de
80 MiB com hashes iguais (`sha256sum` confere); PUT de 3 MB; PUT repetido →
`EXISTS`; GET inexistente → `NOT_FOUND`; senha errada → `AUTH_FAILED`.

## 9. Estado e próximos passos

- [x] Especificação das mensagens de controle (`protocolo.md` §9)
- [x] `files`, `proto`, `auth`, `control`, `server`, `client`, `discovery`, CLIs
- [x] Testes unitários e de ponta a ponta, `go vet`, `staticcheck`, `-race`
- [ ] **Trocar o stub `xfer` pelo SR do Pedro** (`docs/integracao.md` §3). O
      stub é stop-and-wait: inviável para 80 MB com RTT de 100–400 ms.
- [ ] Rodar a mini-CDN em duas máquinas reais (o enunciado exige)
- [ ] Capturas com o Emerson: `tshark -i <if> -f "udp port 9000"` mostrando
      PING/PONG (seleção), HELLO/CHALLENGE/AUTH, GET/META, DATA/ACK, FIN.

## 10. Perguntas que podem cair na apresentação

- *Por que o servidor guarda a última resposta?* Para retransmissões de
  requisição não executarem a operação duas vezes (idempotência).
- *O que acontece se o META se perder? E o META_ACK?* O cliente reenvia
  GET/PUT com o mesmo `Seq` e recebe a resposta guardada.
- *Por que gravar em temporário e renomear?* Para nunca expor arquivo
  incompleto ou corrompido; o rename é atômico.
- *Como a senha é verificada sem ser enviada?* HMAC do Session ID + nonce
  com chave derivada da senha; o servidor recalcula e compara.
- *Por que um Transfer ID além do Session ID?* Para separar transferências
  da mesma sessão e descartar datagramas atrasados de uma transferência
  antiga.
- *Como um servidor com um socket atende vários clientes?* Demultiplexação
  por `(Session ID, Transfer ID)` no laço principal; cada transferência lê
  uma fila própria (vconn).
- *Por que mediana do RTT?* Robusta a outliers.
- *Por que PING não precisa de senha?* Vem antes da escolha, não revela nada
  e não muda estado.
