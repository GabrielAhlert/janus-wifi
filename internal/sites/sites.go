// Package sites gerencia os sites: cifra/decifra a configuração do
// controlador e mantém em cache uma instância do plugin Wi-Fi por site.
package sites

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"janus/internal/core"
	"janus/internal/plugin/wifi"
	"janus/internal/store/postgres"
	"janus/internal/vault"
)

var ErrNoController = errors.New("nenhum controlador Wi-Fi configurado para este site")

var configAAD = []byte("janus/site/controller")

type Service struct {
	db    *postgres.DB
	vault *vault.Vault

	mu          sync.Mutex
	controllers map[int64]cachedController
}

type cachedController struct {
	version time.Time
	ctrl    wifi.Controller
}

func New(db *postgres.DB, v *vault.Vault) *Service {
	return &Service{db: db, vault: v, controllers: map[int64]cachedController{}}
}

// List devolve os sites sem decifrar a configuração dos controladores.
func (s *Service) List(ctx context.Context) ([]core.Site, error) {
	return s.db.Sites(ctx)
}

func (s *Service) Get(ctx context.Context, id int64) (core.Site, error) {
	site, err := s.db.Site(ctx, id)
	if err != nil {
		return site, err
	}
	return site, s.open(ctx, &site)
}

func (s *Service) BySlug(ctx context.Context, slug string) (core.Site, error) {
	site, err := s.db.SiteBySlug(ctx, slug)
	if err != nil {
		return site, err
	}
	return site, s.open(ctx, &site)
}

// Create cria o site com os campos e termos padrão.
func (s *Service) Create(ctx context.Context, site *core.Site) error {
	if err := site.Validate(); err != nil {
		return err
	}
	if err := s.seal(ctx, site); err != nil {
		return err
	}
	return s.db.CreateSite(ctx, site, core.DefaultFields(), core.DefaultTerms())
}

func (s *Service) Save(ctx context.Context, site *core.Site) error {
	if err := site.Validate(); err != nil {
		return err
	}
	if err := s.seal(ctx, site); err != nil {
		return err
	}
	return s.db.UpdateSite(ctx, site)
}

// Controller devolve o plugin Wi-Fi do site, recriado sempre que o site muda.
func (s *Service) Controller(site core.Site) (wifi.Controller, error) {
	if site.Controller == "" {
		return nil, ErrNoController
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.controllers[site.ID]; ok && c.version.Equal(site.UpdatedAt) {
		return c.ctrl, nil
	}
	d, ok := wifi.Lookup(site.Controller)
	if !ok {
		return nil, fmt.Errorf("plugin Wi-Fi %q não está disponível nesta versão", site.Controller)
	}
	ctrl, err := d.New(site.ControllerConfig)
	if err != nil {
		return nil, err
	}
	s.controllers[site.ID] = cachedController{site.UpdatedAt, ctrl}
	return ctrl, nil
}

func (s *Service) open(ctx context.Context, site *core.Site) error {
	site.ControllerConfig = map[string]string{}
	if len(site.ControllerSealed) == 0 {
		return nil
	}
	pt, err := s.vault.Open(ctx, site.ControllerSealed, configAAD)
	if err != nil {
		return fmt.Errorf("configuração do site %s: %w", site.Slug, err)
	}
	return json.Unmarshal(pt, &site.ControllerConfig)
}

func (s *Service) seal(ctx context.Context, site *core.Site) error {
	if len(site.ControllerConfig) == 0 {
		site.ControllerSealed = nil
		return nil
	}
	pt, err := json.Marshal(site.ControllerConfig)
	if err != nil {
		return err
	}
	site.ControllerSealed, err = s.vault.Seal(ctx, vault.ScopeConfig, time.Now(), pt, configAAD)
	return err
}
