package bundle

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGCReferencesAndStalePlan(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	orphan, _, err := Store(ctx, f.cache, bytes.NewReader([]byte("unreferenced")), 100)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PlanGC(ctx, f.cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Candidates) != 1 || p.Candidates[0].Digest != orphan {
		t.Fatalf("retained bundle content was collectible: %+v", p)
	}
	second, _, err := Store(ctx, f.cache, bytes.NewReader([]byte("later orphan")), 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyGC(ctx, p); err == nil {
		t.Fatal("stale GC plan accepted")
	}
	orphanPath, _ := BlobPath(f.cache, orphan)
	if _, err := os.Stat(orphanPath); err != nil {
		t.Fatal("stale plan deleted content")
	}
	p, err = PlanGC(ctx, f.cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyGC(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{orphan, second} {
		p, _ := BlobPath(f.cache, d)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("unreferenced content not collected")
		}
	}
	for _, a := range f.lock.Assets {
		for _, record := range a.Files {
			if err := VerifyBlob(ctx, f.cache, record.Digest, record.Size); err != nil {
				t.Fatal("retained content deleted", err)
			}
		}
	}
}

func TestGCCorruptReferencesAndCoordination(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(f.cache, ".cinderlock", "refs", "bad.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanGC(ctx, f.cache); err == nil {
		t.Fatal("corrupt retention metadata allowed GC")
	}
	unlock, err := acquireCache(ctx, f.cache, false)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	cancelCtx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, err := PlanGC(cancelCtx, f.cache); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cache coordination ignored cancellation", err)
	}
}

func TestGCMissingRetainedObjectBlocksCleanup(t *testing.T) {
	f := newFixture(t)
	p, _ := BlobPath(f.cache, f.lock.Assets[0].Files[0].Digest)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanGC(context.Background(), f.cache); err == nil {
		t.Fatal("missing retained object did not block cleanup")
	}
}
