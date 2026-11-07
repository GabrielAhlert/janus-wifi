// Package retention aplica o prazo de guarda dos dados de conexão: apaga
// sessões e logs vencidos e destrói as chaves dos meses correspondentes.
package retention

import (
	"context"
	"log/slog"
	"time"

	"janus/internal/store"
	"janus/internal/vault"
)

const (
	firstRun = time.Minute
	interval = 6 * time.Hour
)

type Janitor struct {
	db    store.Store
	vault *vault.Vault
	log   *slog.Logger
}

func New(db store.Store, v *vault.Vault, log *slog.Logger) *Janitor {
	return &Janitor{db: db, vault: v, log: log}
}

func (j *Janitor) Run(ctx context.Context) {
	timer := time.NewTimer(firstRun)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := j.Sweep(ctx, time.Now()); err != nil {
				j.log.Error("rotina de retenção falhou", "err", err)
			}
			timer.Reset(interval)
		}
	}
}

// Cutoff é o início do mês mais antigo que ainda deve ser mantido. Com 12
// meses em 06/11/2026, o corte é 01/11/2025: nunca se guarda menos que o prazo.
func Cutoff(now time.Time, months int) time.Time {
	n := now.UTC()
	return time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -months, 0)
}

// Sweep apaga os dados anteriores ao corte e destrói as chaves dos meses
// correspondentes, o que torna ilegível qualquer cópia, inclusive backups.
func (j *Janitor) Sweep(ctx context.Context, now time.Time) error {
	months, err := j.db.RetentionMonths(ctx)
	if err != nil {
		return err
	}
	cutoff := Cutoff(now, months)
	sessions, events, err := j.db.DeleteConnectionDataBefore(ctx, cutoff)
	if err != nil {
		return err
	}
	ids, err := j.db.DestroyKeysBefore(ctx, string(vault.ScopeConnection), vault.Period(vault.ScopeConnection, cutoff))
	if err != nil {
		return err
	}
	j.vault.Forget(ids...)
	if sessions+events > 0 || len(ids) > 0 {
		j.log.Info("retenção aplicada", "corte", cutoff.Format("2006-01-02"), "sessoes", sessions, "eventos", events, "chaves_destruidas", len(ids))
	}
	return nil
}
