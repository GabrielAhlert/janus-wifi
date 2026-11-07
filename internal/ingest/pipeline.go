// Package ingest recebe mensagens do servidor syslog, escolhe o parser pela
// origem, cifra os eventos e os grava em lote, encadeados por hash.
package ingest

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"janus/internal/core"
	"janus/internal/plugin/logs"
	"janus/internal/vault"
)

// Store é o que o pipeline precisa da persistência.
type Store interface {
	LogSources(ctx context.Context) ([]core.LogSource, error)
	LastLogHash(ctx context.Context) ([]byte, error)
	InsertLogEvents(ctx context.Context, recs []core.LogRecord) error
}

const (
	queueSize    = 10000
	batchSize    = 500
	flushEvery   = time.Second
	refreshEvery = 30 * time.Second
)

var logAAD = []byte("janus/log_event")

type route struct {
	sourceID int64
	parser   logs.Parser
}

type item struct {
	at       time.Time
	sourceID int64
	ev       core.LogEvent
}

// Stats são contadores desde o início do processo, exibidos no painel.
type Stats struct {
	Queued  int
	Stored  uint64
	Ignored uint64 // linhas que o parser considerou irrelevantes
	Unknown uint64 // mensagens de IPs não cadastrados como fonte
	Dropped uint64 // descartadas com a fila cheia
	Failed  uint64 // perdidas por erro de gravação
}

type Pipeline struct {
	store Store
	vault *vault.Vault
	log   *slog.Logger
	queue chan item

	mu     sync.RWMutex
	routes map[netip.Addr]route

	stored, ignored, unknown, dropped, failed atomic.Uint64
}

func New(store Store, v *vault.Vault, log *slog.Logger) *Pipeline {
	return &Pipeline{store: store, vault: v, log: log, queue: make(chan item, queueSize), routes: map[netip.Addr]route{}}
}

func (p *Pipeline) Stats() Stats {
	return Stats{
		Queued:  len(p.queue),
		Stored:  p.stored.Load(),
		Ignored: p.ignored.Load(),
		Unknown: p.unknown.Load(),
		Dropped: p.dropped.Load(),
		Failed:  p.failed.Load(),
	}
}

// Handle é chamado pelo servidor syslog para cada mensagem. Não bloqueia:
// com a fila cheia, a mensagem é descartada e contada.
func (p *Pipeline) Handle(from netip.Addr, msg string) {
	p.mu.RLock()
	r, ok := p.routes[from]
	p.mu.RUnlock()
	if !ok {
		p.unknown.Add(1)
		return
	}
	ev, ok := r.parser.Parse(msg)
	if !ok {
		p.ignored.Add(1)
		return
	}
	select {
	case p.queue <- item{at: time.Now().UTC().Truncate(time.Microsecond), sourceID: r.sourceID, ev: ev}:
	default:
		p.dropped.Add(1)
	}
}

// Run é o único escritor da tabela de eventos, o que mantém a cadeia de
// hashes linear. Por isso só pode haver uma instância rodando o pipeline.
func (p *Pipeline) Run(ctx context.Context) error {
	if err := p.refresh(ctx); err != nil {
		return err
	}
	last, err := p.store.LastLogHash(ctx)
	if err != nil {
		return err
	}
	if last == nil {
		last = genesis()
	}

	refresh := time.NewTicker(refreshEvery)
	defer refresh.Stop()
	flush := time.NewTicker(flushEvery)
	defer flush.Stop()

	batch := make([]item, 0, batchSize)
	for {
		select {
		case <-ctx.Done():
			// drena o que já está na fila antes de sair
			for len(p.queue) > 0 && len(batch) < cap(batch)*4 {
				batch = append(batch, <-p.queue)
			}
			if len(batch) > 0 {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				p.flush(shutdownCtx, last, batch)
				cancel()
			}
			return nil
		case it := <-p.queue:
			batch = append(batch, it)
			if len(batch) >= batchSize {
				last = p.flush(ctx, last, batch)
				batch = batch[:0]
			}
		case <-flush.C:
			if len(batch) > 0 {
				last = p.flush(ctx, last, batch)
				batch = batch[:0]
			}
		case <-refresh.C:
			if err := p.refresh(ctx); err != nil {
				p.log.Warn("não foi possível recarregar as fontes de log", "err", err)
			}
		}
	}
}

// flush cifra, encadeia e grava o lote. Devolve o novo último hash; se a
// gravação falhar, devolve prev para a cadeia continuar íntegra.
func (p *Pipeline) flush(ctx context.Context, prev []byte, batch []item) []byte {
	recs := make([]core.LogRecord, 0, len(batch))
	head := prev
	for _, it := range batch {
		payload, err := json.Marshal(it.ev)
		if err != nil {
			continue
		}
		sealed, err := p.vault.Seal(ctx, vault.ScopeConnection, it.at, payload, logAAD)
		if err != nil {
			p.log.Error("falha ao cifrar evento de log", "err", err)
			p.failed.Add(1)
			continue
		}
		rec := core.LogRecord{
			ReceivedAt: it.at,
			SourceID:   it.sourceID,
			SrcIPIndex: p.vault.BlindIndex(core.IndexIP, it.ev.SrcIP),
			Payload:    sealed,
			PrevHash:   head,
		}
		if it.ev.SrcMAC != "" {
			rec.SrcMACIndex = p.vault.BlindIndex(core.IndexMAC, it.ev.SrcMAC)
		}
		rec.Hash = HashRecord(head, rec)
		head = rec.Hash
		recs = append(recs, rec)
	}
	if len(recs) == 0 {
		return prev
	}
	if err := p.store.InsertLogEvents(ctx, recs); err != nil {
		p.log.Error("falha ao gravar eventos de log", "eventos", len(recs), "err", err)
		p.failed.Add(uint64(len(recs)))
		return prev
	}
	p.stored.Add(uint64(len(recs)))
	return head
}

func (p *Pipeline) refresh(ctx context.Context) error {
	sources, err := p.store.LogSources(ctx)
	if err != nil {
		return err
	}
	routes := make(map[netip.Addr]route, len(sources))
	for _, s := range sources {
		if !s.Enabled {
			continue
		}
		d, ok := logs.Lookup(s.Parser)
		if !ok {
			p.log.Warn("fonte de log com parser desconhecido", "fonte", s.Name, "parser", s.Parser)
			continue
		}
		routes[s.SenderIP] = route{sourceID: s.ID, parser: d.New()}
	}
	p.mu.Lock()
	p.routes = routes
	p.mu.Unlock()
	return nil
}
