// Package store define a persistência do Janus como uma interface, com dois
// drivers: sqlite (padrão, arquivo local) e postgres (servidor externo).
// Os drivers só leem e gravam: a criptografia acontece antes, nos serviços,
// e aqui chegam apenas bytes cifrados.
//
// Os dois drivers são validados pela mesma suíte de contrato (storetest).
package store

import (
	"context"
	"errors"
	"time"

	"janus/internal/core"
)

var (
	ErrNotFound = errors.New("registro não encontrado")
	ErrConflict = errors.New("registro duplicado")
)

// DefaultRetentionMonths segue o prazo mínimo do Marco Civil (art. 13).
const DefaultRetentionMonths = 12

type Store interface {
	// Migrate aplica as migrações pendentes do driver.
	Migrate(ctx context.Context) error
	// Describe identifica o banco para o painel, sem credenciais.
	Describe() string
	Close()

	// Chaves de dados do vault (implementa vault.KeyStore).
	FindKey(ctx context.Context, scope, period string) (id uint32, wrapped []byte, err error)
	CreateKey(ctx context.Context, scope, period string, wrapped []byte) (id uint32, stored []byte, err error)
	GetKey(ctx context.Context, id uint32) (scope, period string, wrapped []byte, err error)
	// DestroyKeysBefore apaga as chaves de um escopo anteriores ao período (AAAA-MM).
	DestroyKeysBefore(ctx context.Context, scope, period string) ([]uint32, error)
	// HasDataKeys informa se o banco já tem alguma chave, ou seja, dados cifrados.
	HasDataKeys(ctx context.Context) (bool, error)

	Sites(ctx context.Context) ([]core.Site, error)
	Site(ctx context.Context, id int64) (core.Site, error)
	SiteBySlug(ctx context.Context, slug string) (core.Site, error)
	// CreateSite cria o site já com os campos e a primeira versão dos termos.
	CreateSite(ctx context.Context, s *core.Site, fields []core.Field, terms core.Terms) error
	UpdateSite(ctx context.Context, s *core.Site) error

	// Fields devolve todos os campos do site (ativos e inativos) na ordem de exibição.
	Fields(ctx context.Context, siteID int64) ([]core.Field, error)
	Field(ctx context.Context, siteID, id int64) (core.Field, error)
	CreateField(ctx context.Context, f *core.Field) error
	// UpdateField altera tudo menos a chave, que identifica o dado já coletado.
	UpdateField(ctx context.Context, f core.Field) error
	DeleteField(ctx context.Context, siteID, id int64) error

	// CurrentTerms devolve a versão vigente (a mais recente) dos termos do site.
	CurrentTerms(ctx context.Context, siteID int64) (core.Terms, error)
	TermsHistory(ctx context.Context, siteID int64) ([]core.Terms, error)
	// PublishTerms grava uma nova versão; versões anteriores nunca são alteradas.
	PublishTerms(ctx context.Context, siteID int64, title, body string, adminID int64) (core.Terms, error)

	// CreateSession grava a sessão e seus índices cegos numa única transação.
	CreateSession(ctx context.Context, s *core.SessionRecord, index []core.IndexEntry) error
	SessionCountsSince(ctx context.Context, since time.Time) (map[int64]int64, error)
	// DeleteConnectionDataBefore remove sessões e eventos de log anteriores a cutoff.
	DeleteConnectionDataBefore(ctx context.Context, cutoff time.Time) (sessions, events int64, err error)

	LogSources(ctx context.Context) ([]core.LogSource, error)
	CreateLogSource(ctx context.Context, s *core.LogSource) error
	DeleteLogSource(ctx context.Context, id int64) error
	// LastLogHash devolve o hash do último evento gravado, ou nil se não houver.
	LastLogHash(ctx context.Context) ([]byte, error)
	// InsertLogEvents grava um lote; a ordem do lote vira a ordem dos ids.
	InsertLogEvents(ctx context.Context, recs []core.LogRecord) error
	// ScanLogEvents percorre todos os eventos em ordem de id.
	ScanLogEvents(ctx context.Context, fn func(core.LogRecord) error) error
	LogEventCountSince(ctx context.Context, since time.Time) (int64, error)

	CreateAdmin(ctx context.Context, email, passwordHash string) error
	// AdminCredentials devolve o administrador e o hash da senha para o login.
	AdminCredentials(ctx context.Context, email string) (core.Admin, string, error)
	CreateAdminSession(ctx context.Context, tokenHash []byte, adminID int64, expires time.Time) error
	AdminBySession(ctx context.Context, tokenHash []byte) (core.Admin, error)
	DeleteAdminSession(ctx context.Context, tokenHash []byte) error
	// Audit registra uma ação administrativa.
	Audit(ctx context.Context, adminID int64, action string, detail any) error

	CreateAsset(ctx context.Context, mime string, data []byte) (int64, error)
	Asset(ctx context.Context, id int64) (mime string, data []byte, err error)

	RetentionMonths(ctx context.Context) (int, error)
	SetRetentionMonths(ctx context.Context, months int) error
}
