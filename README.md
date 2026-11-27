# Sigma Protocol

Trabalho de Redes de Computadores II: transferência confiável de arquivos sobre UDP.

- [Enunciado](tp-rc2.pdf)
- [Plano de implementação](docs/plano-de-implementacao.md)
- [Passo a passo da etapa 1](docs/passos.md)
- [Especificação do protocolo](docs/protocolo.md)
- [Aplicação, arquivos, autenticação e mini-CDN](docs/aplicacao.md)
- [Integração transporte ↔ aplicação](docs/integracao.md)
- [Modelo SBC](article/main.tex)

## Ambiente

Go, LaTeX e ferramentas de experimentação:

```sh
nix develop path:.
# Ou, sem flakes:
nix-shell
```

## Executar

```sh
go build -o bin/ ./cmd/...

# Arquivo de teste de 80 MiB (fora do Git)
mkdir -p shared && head -c 83886080 /dev/urandom > shared/teste.bin

# Servidores (a senha vem do ambiente, nunca de flag)
export SIGMA_PASSWORD=segredo
bin/sigma-server -bind 127.0.0.1:9000 -dir shared &
bin/sigma-server -bind 127.0.0.1:9001 -dir shared &

# Cliente: com vários servidores, mede o RTT e escolhe o mais rápido (mini-CDN)
C="bin/sigma-client -servers 127.0.0.1:9000,127.0.0.1:9001"
$C probe                          # só a medição de RTT e a escolha
$C list
$C -o downloads get teste.bin     # mostra sha256 original e recebido
$C put caminho/do/arquivo
$C -server 127.0.0.1:9001 get teste.bin   # força um servidor
$C -csv metricas.csv get teste.bin        # grava métricas da transferência
```

As flags vêm antes do comando; use `-h` para ver todas. `-sim-loss` e
`-sim-delay` simulam perda/atraso na própria aplicação, para testes sem
`tc netem`. Detalhes do fluxo em [docs/aplicacao.md](docs/aplicacao.md).

> A transferência ainda usa o stub stop-and-wait de `internal/xfer`; a troca
> pelo Selective Repeat está descrita em [docs/integracao.md](docs/integracao.md).

```sh
go build ./...
go test ./...
go vet ./...
staticcheck ./...
go test -run='^$' -fuzz=FuzzDecode -fuzztime=60s ./internal/wire/
```

`go test -race` precisa de cgo. Se o caminho do projeto tiver espaços, o
`nix develop` gera um `-L` quebrado em `NIX_LDFLAGS`; remova-o antes:

```sh
export NIX_LDFLAGS=$(echo "$NIX_LDFLAGS" | tr ' ' '\n' | grep -v outputs/out/lib | tr '\n' ' ')
go test -race ./...
```

## Relatório

```sh
make -C article
# PDF: article/main.pdf
```
