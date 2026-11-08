package bundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
)

type cacheReference struct {
	Owner   string   `json:"owner"`
	Digests []string `json:"digests"`
}
type GCPlan struct {
	Format           string            `json:"format"`
	Cache            string            `json:"cache"`
	ReferencesDigest string            `json:"referencesDigest"`
	Candidates       []spec.Descriptor `json:"candidates"`
	Bytes            int64             `json:"bytes"`
}

func acquireCache(ctx context.Context, cache string, initialize bool) (func(), error) {
	meta := filepath.Join(cache, ".cinderlock")
	if initialize {
		if err := os.MkdirAll(filepath.Join(meta, "refs"), 0700); err != nil {
			return nil, err
		}
	}
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if initialize {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Open(filepath.Join(meta, "lock"), flags, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "cache lock")
	for {
		if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
			return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = f.Close() }, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func retainCache(cache, owner string, assets []spec.LockedAsset) error {
	ref := cacheReference{Owner: owner}
	seen := map[string]bool{}
	for _, a := range assets {
		for _, f := range a.Files {
			if !ValidDigest(f.Digest) {
				return errors.New("invalid retained digest")
			}
			seen[f.Digest] = true
		}
	}
	for d := range seen {
		ref.Digests = append(ref.Digests, d)
	}
	sort.Strings(ref.Digests)
	b, err := spec.Canonical(ref)
	if err != nil {
		return err
	}
	p := filepath.Join(cache, ".cinderlock", "refs", spec.Hash(b)[7:]+".json")
	if old, err := os.ReadFile(p); err == nil {
		if string(old) != string(b) {
			return errors.New("cache reference identity conflict")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeExclusive(p, b, 0600)
}

func PlanGC(ctx context.Context, cache string) (GCPlan, error) {
	abs, err := filepath.Abs(cache)
	if err != nil {
		return GCPlan{}, err
	}
	release, err := acquireCache(ctx, abs, false)
	if err != nil {
		return GCPlan{}, err
	}
	defer release()
	return planGC(ctx, abs)
}
func planGC(ctx context.Context, cache string) (GCPlan, error) {
	p := GCPlan{Format: "cinderlock.cache-gc.v1", Cache: cache, Candidates: []spec.Descriptor{}}
	entries, err := os.ReadDir(filepath.Join(cache, ".cinderlock", "refs"))
	if err != nil {
		return p, err
	}
	if len(entries) > 100000 {
		return p, errors.New("too many retention records")
	}
	kept := map[string]bool{}
	refs := []cacheReference{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return p, errors.New("unrecognized cache retention record")
		}
		f, err := os.Open(filepath.Join(cache, ".cinderlock", "refs", entry.Name()))
		if err != nil {
			return p, err
		}
		var ref cacheReference
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return p, err
		}
		if info.Size() > MaxMetadataBytes {
			f.Close()
			return p, errors.New("oversized retention record")
		}
		b, err := os.ReadFile(f.Name())
		f.Close()
		if err != nil {
			return p, err
		}
		if err := strictJSON(b, &ref, true); err != nil {
			return p, err
		}
		if ref.Owner == "" || entry.Name() != spec.Hash(b)[7:]+".json" {
			return p, errors.New("cache reference identity mismatch")
		}
		for _, d := range ref.Digests {
			if !ValidDigest(d) {
				return p, errors.New("invalid retention digest")
			}
			kept[d] = true
		}
		refs = append(refs, ref)
	}
	for d := range kept {
		retainedPath, _ := BlobPath(cache, d)
		info, err := os.Lstat(retainedPath)
		if err != nil {
			return p, fmt.Errorf("retained cache content is missing: %w", err)
		}
		if !info.Mode().IsRegular() {
			return p, errors.New("retained cache content is not a regular file")
		}
	}
	p.ReferencesDigest, err = spec.Digest(refs)
	if err != nil {
		return p, err
	}
	blobs, err := os.ReadDir(filepath.Join(cache, "blobs", "sha256"))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	for _, entry := range blobs {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		d := "sha256:" + entry.Name()
		if strings.HasPrefix(entry.Name(), ".partial-") {
			continue
		}
		if !ValidDigest(d) || entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return p, errors.New("unrecognized cache content blocks garbage collection")
		}
		if kept[d] {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return p, err
		}
		if !info.Mode().IsRegular() {
			return p, errors.New("non-regular cache object")
		}
		p.Candidates = append(p.Candidates, spec.Descriptor{Path: "blobs/sha256/" + entry.Name(), Digest: d, Size: info.Size()})
		p.Bytes += info.Size()
	}
	return p, nil
}

func ApplyGC(ctx context.Context, plan GCPlan) error {
	if plan.Format != "cinderlock.cache-gc.v1" || !filepath.IsAbs(plan.Cache) {
		return errors.New("invalid garbage-collection plan")
	}
	release, err := acquireCache(ctx, plan.Cache, false)
	if err != nil {
		return err
	}
	defer release()
	current, err := planGC(ctx, plan.Cache)
	if err != nil {
		return err
	}
	a, err := spec.Digest(plan)
	if err != nil {
		return err
	}
	b, err := spec.Digest(current)
	if err != nil {
		return err
	}
	if a != b {
		return spec.Err(11, "cache garbage-collection plan is stale")
	}
	for _, d := range plan.Candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		p, err := BlobPath(plan.Cache, d.Digest)
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil {
			return fmt.Errorf("remove unused cache object: %w", err)
		}
	}
	return nil
}
