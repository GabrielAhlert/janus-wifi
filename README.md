# Janus Wi-Fi

Portal cativo para Wi-Fi corporativo de visitantes. O Janus cadastra o visitante, libera o acesso no controlador Wi-Fi e guarda os registros de conexão exigidos pelo Marco Civil da Internet. Os dados pessoais ficam cifrados, e os logs ficam encadeados por hash para que qualquer adulteração seja detectável.

- **Modular**: controladores Wi-Fi e fontes de log são plugins. Hoje estão disponíveis UniFi (controlador) e UCG/UDM (logs).
- **Personalizável pelo painel**: logo, imagem de fundo, cores, textos, CSS, campos do formulário e termos de uso versionados, com pré-visualização ao vivo.
- **Cifrado de verdade**: envelope encryption com AES-256-GCM, índice cego para buscas e destruição de chaves (crypto-shredding) ao fim da retenção.

## Arquitetura

```
cmd/janus/                 CLI: serve, keygen, admin-create, verify-logs
internal/
  core/                    domínio puro: Site, Field, Theme, Terms, LogEvent...
  config/                  variáveis de ambiente
  vault/                   criptografia: DEKs por mês, KEK, índice cego
  store/                   interface Store (só recebe bytes já cifrados)
    sqlite/                driver padrão: arquivo local, container único
    postgres/              driver para Postgres externo
    storetest/             suíte de contrato que os dois drivers passam
  plugin/
    config.go              descrição dos campos de config que o painel renderiza
    wifi/                  interface Controller + registro de drivers
      unifi/               driver UniFi (External Portal)
    logs/                  interface Parser + registro de drivers
      kv/                  extrator chave=valor compartilhado pelos parsers
      ucg/                 parser do syslog de gateways UniFi
    all/                   imports que habilitam os plugins embutidos
  sites/                   config do controlador (cifrada) + cache de plugins
  hotspot/                 caso de uso central: validar → gravar → liberar
  portal/                  portal cativo (visitantes)
  admin/                   painel (um arquivo por página)
  syslog/                  receptor UDP/TCP
  ingest/                  pipeline de logs: parse → cifra → cadeia de hashes
  retention/               apaga dados vencidos e destrói as chaves
  app/                     monta tudo e sobe os serviços
web/                       templates e estáticos embutidos no binário
```

Regra de dependência: `core` não importa nada interno. Plugins dependem só de `core` e `plugin`. `app` é o único pacote que conhece todos os outros.

### Fluxo do visitante

1. O visitante entra no SSID de visitantes. O UniFi o redireciona para `http://<janus>/guest/s/<site>/?id=<mac>&ap=...&url=...`.
2. O portal mostra o formulário do site, com os campos, o visual e os termos configurados no painel. O MAC vai num *ticket* assinado por HMAC, então o formulário não consegue trocá-lo.
3. No envio, o `hotspot` valida e normaliza os campos (CPF com dígito verificador, e-mail, telefone), cifra o cadastro, grava a sessão com a versão dos termos aceita e só então chama `authorize-guest` no controlador.

### Criptografia

| Dado | Como fica no banco |
|---|---|
| Campos "Cifrado" | AES-256-GCM dentro de `sessions.payload` |
| Campos "Cifrado + pesquisável" | Cifrado, mais um HMAC em `session_index` para busca exata |
| Campos "Texto puro" | `sessions.data_plain` (use só para dados não pessoais) |
| MAC e IP do visitante | Cifrados, mais um índice cego (cruzam sessões com logs sem decifrar) |
| Eventos de firewall/DHCP | Cifrados, com índice cego de IP/MAC e encadeados por SHA-256 |
| Credenciais do controlador | Cifradas no escopo `config` |

- Há uma chave de dados (DEK) por mês, guardada cifrada pela KEK. A KEK e as chaves de índice e de assinatura são derivadas da **chave mestra** via HKDF.
- **A chave mestra nunca vai para o banco.** Sem ela, nem um dump completo revela os dados. Se você perder a chave, os dados se perdem também: guarde uma cópia num cofre.
- Para trocar a chave local por um KMS ou HashiCorp Vault, basta implementar `vault.Wrapper`.
- Ao fim da retenção (12 meses por padrão, configurável), a rotina apaga as linhas **e destrói a DEK do mês**. Isso torna ilegíveis também as cópias em backup.

## Rodando

A imagem é publicada em `ghcr.io/gabrielahlert/janus-wifi` a cada push na `main` (tag `main`) e a cada versão (`vX.Y.Z` e `latest`).

### Banco de dados

O banco é escolhido por `JANUS_DATABASE_URL`:

| Valor | Quando usar |
|---|---|
| `sqlite:///data/janus.db` (padrão) | Instalação de um container só, como no Unraid. O backup é um arquivo. |
| `postgres://usuario:senha@host:5432/janus` | Quando você já tem um Postgres, ou com volume de syslog muito alto: o SQLite aceita um escritor por vez. |

Não há migração automática entre os dois: escolha na instalação.

### Chave mestra

Se `JANUS_MASTER_KEY_FILE` (na imagem, `/secrets/master_key`) não existir e o banco estiver vazio, o Janus **gera a chave na primeira inicialização** e avisa no log. **Faça backup desse arquivo fora do servidor:** sem ele, os dados ficam ilegíveis. Se o banco já tiver dados e a chave sumir, o Janus se recusa a subir, em vez de gerar outra.

### Unraid

O UniFi exige o portal na porta 80, que a interface do Unraid já usa. Por isso o Janus roda com **IP próprio na `br0`**.

1. Copie [deploy/unraid/janus-wifi.xml](deploy/unraid/janus-wifi.xml) para `/boot/config/plugins/dockerMan/templates-user/my-janus-wifi.xml`.
2. Crie as pastas com o dono padrão do Unraid:
   ```bash
   mkdir -p /mnt/user/appdata/janus /mnt/user/appdata/janus-secrets && chown 99:100 /mnt/user/appdata/janus /mnt/user/appdata/janus-secrets && chmod 700 /mnt/user/appdata/janus-secrets
   ```
3. Em *Docker → Add Container*, escolha o template **janus-wifi**. Defina um IP fixo livre da LAN de gestão (ex.: `192.168.1.50`) e, em *Redes com acesso ao painel*, a rede da TI. Para usar um Postgres externo, troque *Banco de dados* pela URL dele.
4. Suba o container e confira no log a linha `chave mestra gerada`. **Copie `/mnt/user/appdata/janus-secrets/master_key` para fora do servidor.** A pasta é separada justamente para você poder excluí-la do backup de appdata.
5. Crie o administrador:
   ```bash
   docker exec -it janus-wifi /janus admin-create -email voce@empresa.com
   ```
6. Abra o painel em `http://<IP do container>:8081`.
7. No UCG, permita que a rede de visitantes acesse `<IP do container>` **só na porta 80**, e aponte o syslog para `<IP do container>:514`. Os visitantes chegam roteados (sem NAT), então o IP de cada um fica registrado corretamente.

Para atualizar, use *Force update* na aba Docker. Em produção, fixe uma versão (`:v1.2.3`) no lugar de `:main`.

### Compose (outros servidores)

O [compose.yaml](compose.yaml) é um exemplo com Postgres:

```bash
podman run --rm ghcr.io/gabrielahlert/janus-wifi:main keygen > master_key && chmod 600 master_key
cp .env.example .env   # defina POSTGRES_PASSWORD
podman compose up -d
podman compose exec janus /janus admin-create -email voce@empresa.com
```

- Portal: porta 80, porque o UniFi exige o portal externo nela.
- Painel: `http://127.0.0.1:8081`. Exponha só na rede de gestão ou atrás de um proxy HTTPS. Sem HTTPS, defina `JANUS_INSECURE_COOKIES=1`.
- Syslog: porta 5514, UDP e TCP.

### Variáveis

| Variável | Padrão | |
|---|---|---|
| `JANUS_DATABASE_URL` | `sqlite:///data/janus.db` | `sqlite://` ou `postgres://` |
| `JANUS_MASTER_KEY_FILE` | `/secrets/master_key` (imagem) | gerado no primeiro boot se não existir |
| `JANUS_MASTER_KEY` | | a chave em base64, alternativa ao arquivo |
| `JANUS_PORTAL_ADDR` | `:8080` | |
| `JANUS_ADMIN_ADDR` | `127.0.0.1:8081` | |
| `JANUS_SYSLOG_ADDR` | `:5514` | UDP e TCP |
| `JANUS_ADMIN_ALLOW` | (todas) | redes que podem abrir o painel, ex.: `192.168.1.0/24,10.0.0.5` |
| `JANUS_INSECURE_COOKIES` | | `1` permite login no painel sem HTTPS |

Para conferir a integridade dos logs (útil antes de atender um ofício):

```bash
docker exec janus-wifi /janus verify-logs
```

## Configurando o UniFi

1. **Conta para o Janus**: no UniFi OS, crie um usuário local dedicado. A função *Hotspot Operator* basta.
2. **Rede de visitantes**: em *Settings → Hotspot* (ou *Guest Hotspot*), escolha *External Portal Server* e informe o IP do Janus. Libere o IP do Janus na lista de *Pre-Authorization Access*.
3. **Janus**: no painel, crie um site com o **slug igual ao nome curto do site no UniFi** (normalmente `default`), escolha o plugin *Ubiquiti UniFi* e informe endereço, usuário e senha. Para fixar o certificado autoassinado, preencha o fingerprint SHA-256. Para obtê-lo:

   ```bash
   openssl s_client -connect 192.168.1.1:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
   ```

4. **Logs do UCG**: em *Fontes de log*, cadastre o IP do gateway com o parser *UniFi Gateway*. No UniFi Network, aponte o syslog/SIEM para o Janus (porta 514 no Unraid, 5514 no compose) e ligue o log nas regras de firewall da rede de visitantes.

> **Limitação conhecida:** o log de firewall do UCG mostra o IP interno, mas não o IP/porta públicos pós-NAT. Para responder "quem usava o IP público X, porta Y, às HH:MM", é preciso o log de NAT. O Sophos fornece isso (`tran_src_ip`/`tran_src_port`), e esse é o motivo de ele ser o próximo parser.

## Criando um plugin

**Controlador Wi-Fi** (ex.: Omada, Aruba, MikroTik):

```go
package omada

func init() {
	wifi.Register(wifi.Driver{
		Name:   "omada",
		Label:  "TP-Link Omada",
		Config: []plugin.ConfigField{{Key: "url", Label: "Endereço", Type: plugin.Text, Required: true}},
		New:    New, // func(cfg map[string]string) (wifi.Controller, error)
	})
}
```

Implemente `ParseRedirect`, `Authorize` e `Deauthorize` e adicione o import em `internal/plugin/all/all.go`. O painel gera o formulário de configuração sozinho, e campos `Secret` são cifrados e nunca reexibidos.

**Parser de logs** (ex.: Sophos): implemente `logs.Parser`, que devolve um `core.LogEvent` normalizado, registre com `logs.Register` e importe em `plugin/all`. O pacote `plugin/logs/kv` já interpreta `chave="valor"`.

## Desenvolvimento

```bash
go test ./...
go vet ./...
```

Os testes cobrem a criptografia (incluindo crypto-shredding e chave mestra errada), o driver UniFi contra um controlador falso (login, CSRF, sessão expirada, fixação de certificado), o parser do UCG, a cadeia de hashes (alteração e remoção), a assinatura dos tickets, a validação de CPF/e-mail/telefone e a validação do tema.

Os dois drivers de banco passam pela mesma suíte de contrato (`internal/store/storetest`). O SQLite roda sempre. O Postgres roda quando há um banco disponível, como no CI:

```bash
JANUS_TEST_POSTGRES_URL=postgres://janus:senha@localhost:5432/janus go test ./internal/store/...
```

## Próximos passos

- Tela de **consulta** para requisições judiciais: busca por CPF/e-mail/MAC/IP e período, com justificativa obrigatória registrada na auditoria.
- Parser **Sophos**, com NAT.
- Botão "testar conexão" com o controlador.
- Rate limit no login do painel e no portal.
- Reconhecer visitantes recorrentes (sem pedir o cadastro de novo).
- API key da Integration API do UniFi como alternativa a usuário e senha.
