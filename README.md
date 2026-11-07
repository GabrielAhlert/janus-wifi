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
  store/postgres/          persistência + migrations/ (só bytes já cifrados)
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

Pré-requisitos: Podman (ou Docker) com compose.

```bash
podman build -t janus .
podman run --rm janus keygen > master_key && chmod 600 master_key
cp .env.example .env   # defina POSTGRES_PASSWORD
podman compose up -d
podman compose exec janus /janus admin-create -email voce@empresa.com
```

- Portal: porta 80. O UniFi exige o portal externo na porta 80.
- Painel: `http://127.0.0.1:8081`. Exponha só na rede de gestão ou atrás de um proxy HTTPS. Sem HTTPS, defina `JANUS_INSECURE_COOKIES=1`.
- Syslog: porta 5514, UDP e TCP.

Variáveis: `JANUS_DATABASE_URL`, `JANUS_MASTER_KEY_FILE` (ou `JANUS_MASTER_KEY`), `JANUS_PORTAL_ADDR`, `JANUS_ADMIN_ADDR`, `JANUS_SYSLOG_ADDR`, `JANUS_INSECURE_COOKIES`.

Para conferir a integridade dos logs (útil antes de atender um ofício):

```bash
podman compose exec janus /janus verify-logs
```

## Configurando o UniFi

1. **Conta para o Janus**: no UniFi OS, crie um usuário local dedicado. A função *Hotspot Operator* basta.
2. **Rede de visitantes**: em *Settings → Hotspot* (ou *Guest Hotspot*), escolha *External Portal Server* e informe o IP do Janus. Libere o IP do Janus na lista de *Pre-Authorization Access*.
3. **Janus**: no painel, crie um site com o **slug igual ao nome curto do site no UniFi** (normalmente `default`), escolha o plugin *Ubiquiti UniFi* e informe endereço, usuário e senha. Para fixar o certificado autoassinado, preencha o fingerprint SHA-256. Para obtê-lo:

   ```bash
   openssl s_client -connect 192.168.1.1:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
   ```

4. **Logs do UCG**: em *Fontes de log*, cadastre o IP do gateway com o parser *UniFi Gateway*. No UniFi Network, aponte o syslog/SIEM para o Janus na porta 5514 e ligue o log nas regras de firewall da rede de visitantes.

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

## Próximos passos

- Tela de **consulta** para requisições judiciais: busca por CPF/e-mail/MAC/IP e período, com justificativa obrigatória registrada na auditoria.
- Parser **Sophos**, com NAT.
- Botão "testar conexão" com o controlador.
- Rate limit no login do painel e no portal.
- Reconhecer visitantes recorrentes (sem pedir o cadastro de novo).
- API key da Integration API do UniFi como alternativa a usuário e senha.
