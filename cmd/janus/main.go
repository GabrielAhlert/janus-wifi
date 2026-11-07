// Comando janus: portal cativo corporativo com guarda de logs de conexão.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"janus/internal/app"
	"janus/internal/config"
	_ "janus/internal/plugin/all"
	"janus/internal/vault"
)

const usage = `uso: janus <comando> [opções]

comandos:
  serve         inicia portal, painel, receptor syslog e rotina de retenção
  keygen        gera uma chave mestra nova (base64)
  admin-create  cria um administrador: janus admin-create -email voce@empresa.com
                (senha em JANUS_ADMIN_PASSWORD ou digitada no terminal)
  verify-logs   confere a integridade da cadeia de hashes dos logs
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var err error
	switch os.Args[1] {
	case "serve":
		err = withConfig(func(c config.Config) error { return app.Serve(ctx, c, log) })
	case "keygen":
		fmt.Println(vault.GenerateMasterKey())
	case "admin-create":
		err = adminCreate(ctx, os.Args[2:])
	case "verify-logs":
		err = withConfig(func(c config.Config) error { return app.VerifyLogs(ctx, c, os.Stdout) })
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
}

func withConfig(fn func(config.Config) error) error {
	c, err := config.Load()
	if err != nil {
		return err
	}
	return fn(c)
}

func adminCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("admin-create", flag.ExitOnError)
	email := fs.String("email", "", "e-mail do administrador")
	fs.Parse(args)
	if *email == "" {
		return errors.New("informe -email")
	}
	password := os.Getenv("JANUS_ADMIN_PASSWORD")
	if password == "" {
		fmt.Fprint(os.Stderr, "Senha: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return err
		}
		password = strings.TrimRight(line, "\r\n")
	}
	return withConfig(func(c config.Config) error { return app.CreateAdmin(ctx, c, *email, password) })
}
