// Package app monta as dependências e roda os serviços. É o único lugar que
// conhece todas as peças; os demais pacotes recebem só o que precisam.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"

	"janus/internal/admin"
	"janus/internal/config"
	"janus/internal/hotspot"
	"janus/internal/ingest"
	"janus/internal/portal"
	"janus/internal/retention"
	"janus/internal/sites"
	"janus/internal/store/postgres"
	"janus/internal/syslog"
	"janus/internal/vault"
	"janus/web"
)

// Serve roda portal, painel, receptor syslog, pipeline de logs e retenção
// até ctx ser cancelado.
func Serve(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	db, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	keys, err := vault.DeriveKeys(cfg.MasterKey)
	if err != nil {
		return err
	}
	wrapper, err := vault.NewLocalWrapper(keys.Wrap)
	if err != nil {
		return err
	}
	v := vault.New(wrapper, db, keys.Index)

	tmpl, err := web.Load()
	if err != nil {
		return fmt.Errorf("templates: %w", err)
	}

	siteSvc := sites.New(db, v)
	hotspotSvc := hotspot.New(db, v, siteSvc, log)
	portalH := portal.New(db, siteSvc, hotspotSvc, portal.NewSigner(keys.Token), tmpl.Portal, log)
	pipeline := ingest.New(db, v, log)
	adminH := admin.New(admin.Deps{
		DB: db, Sites: siteSvc, Portal: portalH, Templates: tmpl.Admin,
		Stats: pipeline.Stats, Log: log, SecureCookies: cfg.SecureCookies,
	})
	syslogSrv := &syslog.Server{Addr: cfg.SyslogAddr, Handler: pipeline.Handle, Log: log}
	janitor := retention.New(db, v, log)

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return serveHTTP(ctx, "portal", cfg.PortalAddr, portalH.Routes(), log) })
	g.Go(func() error { return serveHTTP(ctx, "admin", cfg.AdminAddr, adminH.Routes(), log) })
	g.Go(func() error { return syslogSrv.Run(ctx) })
	g.Go(func() error { return pipeline.Run(ctx) })
	g.Go(func() error { janitor.Run(ctx); return nil })
	return g.Wait()
}

func serveHTTP(ctx context.Context, name, addr string, h http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("http escutando", "servico", name, "addr", addr)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return fmt.Errorf("%s: %w", name, err)
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

// CreateAdmin cria um administrador do painel.
func CreateAdmin(ctx context.Context, cfg config.Config, email, password string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if len(password) < 10 {
		return errors.New("a senha deve ter pelo menos 10 caracteres")
	}
	db, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := db.CreateAdmin(ctx, email, string(hash)); errors.Is(err, postgres.ErrConflict) {
		return fmt.Errorf("já existe um administrador com o e-mail %s", email)
	} else if err != nil {
		return err
	}
	fmt.Printf("administrador %s criado\n", email)
	return nil
}

// VerifyLogs confere a cadeia de hashes dos eventos de log.
func VerifyLogs(ctx context.Context, cfg config.Config, out io.Writer) error {
	db, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	rep, err := ingest.Verify(ctx, db.ScanLogEvents)
	if err != nil {
		return fmt.Errorf("cadeia de logs INVÁLIDA após %d eventos íntegros: %w", rep.Records, err)
	}
	if rep.Records == 0 {
		fmt.Fprintln(out, "nenhum evento de log gravado")
		return nil
	}
	fmt.Fprintf(out, "cadeia íntegra: %d eventos (ids %d a %d)\n", rep.Records, rep.FirstID, rep.LastID)
	return nil
}

func openDB(ctx context.Context, cfg config.Config) (*postgres.DB, error) {
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrar banco: %w", err)
	}
	return db, nil
}
