package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	"janus/internal/core"
)

// genesis é o prev_hash do primeiro evento da tabela.
func genesis() []byte { return make([]byte, sha256.Size) }

// HashRecord encadeia um evento ao anterior. Qualquer alteração, inserção
// ou remoção no meio da tabela quebra a cadeia a partir daquele ponto.
func HashRecord(prev []byte, r core.LogRecord) []byte {
	h := sha256.New()
	writeField(h, prev)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(r.ReceivedAt.UnixMicro()))
	h.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(r.SourceID))
	h.Write(n[:])
	writeField(h, r.SrcIPIndex)
	writeField(h, r.SrcMACIndex)
	writeField(h, r.Payload)
	return h.Sum(nil)
}

func writeField(h hash.Hash, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	h.Write(n[:])
	h.Write(b)
}

type Report struct {
	Records         int64
	FirstID, LastID int64
}

type ChainError struct {
	ID     int64
	Reason string
}

func (e *ChainError) Error() string { return fmt.Sprintf("evento %d: %s", e.ID, e.Reason) }

// Scanner percorre os eventos em ordem de id (ver postgres.DB.ScanLogEvents).
type Scanner func(ctx context.Context, fn func(core.LogRecord) error) error

// Verify confere a cadeia inteira. O primeiro evento restante serve de
// âncora, já que a retenção apaga os mais antigos.
func Verify(ctx context.Context, scan Scanner) (Report, error) {
	var rep Report
	var prev []byte
	err := scan(ctx, func(r core.LogRecord) error {
		if rep.Records == 0 {
			rep.FirstID = r.ID
		} else if !bytes.Equal(r.PrevHash, prev) {
			return &ChainError{r.ID, "não aponta para o evento anterior (evento removido ou inserido)"}
		}
		if !bytes.Equal(HashRecord(r.PrevHash, r), r.Hash) {
			return &ChainError{r.ID, "conteúdo alterado"}
		}
		prev = r.Hash
		rep.Records++
		rep.LastID = r.ID
		return nil
	})
	return rep, err
}
