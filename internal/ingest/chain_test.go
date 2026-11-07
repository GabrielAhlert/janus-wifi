package ingest

import (
	"context"
	"errors"
	"testing"
	"time"

	"janus/internal/core"
)

func buildChain(n int) []core.LogRecord {
	prev := genesis()
	recs := make([]core.LogRecord, n)
	for i := range recs {
		r := core.LogRecord{
			ID:         int64(i + 1),
			ReceivedAt: time.Date(2026, 11, 6, 10, 0, i, 0, time.UTC),
			SourceID:   1,
			SrcIPIndex: []byte{byte(i)},
			Payload:    []byte("cifrado"),
			PrevHash:   prev,
		}
		r.Hash = HashRecord(prev, r)
		prev = r.Hash
		recs[i] = r
	}
	return recs
}

func scannerOf(recs []core.LogRecord) Scanner {
	return func(_ context.Context, fn func(core.LogRecord) error) error {
		for _, r := range recs {
			if err := fn(r); err != nil {
				return err
			}
		}
		return nil
	}
}

func TestVerifyIntactChain(t *testing.T) {
	rep, err := Verify(context.Background(), scannerOf(buildChain(5)))
	if err != nil || rep.Records != 5 || rep.FirstID != 1 || rep.LastID != 5 {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
}

func TestVerifyAcceptsTruncatedStart(t *testing.T) {
	// A retenção apaga os primeiros eventos; o restante continua válido.
	if _, err := Verify(context.Background(), scannerOf(buildChain(5)[2:])); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	tampered := buildChain(5)
	tampered[2].Payload = []byte("alterado")
	removed := append(buildChain(5)[:2:2], buildChain(5)[3:]...)

	for name, recs := range map[string][]core.LogRecord{"alterado": tampered, "removido": removed} {
		_, err := Verify(context.Background(), scannerOf(recs))
		var ce *ChainError
		if !errors.As(err, &ce) || ce.ID != 3 && ce.ID != 4 {
			t.Fatalf("%s: erro = %v, esperado ChainError no evento 3 ou 4", name, err)
		}
	}
}
