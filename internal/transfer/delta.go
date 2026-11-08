package transfer

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

const DeltaName = "cinderlock-delta.json"

type DeltaManifest struct {
	Format       string            `json:"format"`
	BaseDigest   string            `json:"baseDigest"`
	TargetDigest string            `json:"targetDigest"`
	Changed      []spec.Descriptor `json:"changed"`
}

func CreateDelta(ctx context.Context, base, target *bundle.Verified, outDir string) (DeltaManifest, error) {
	m := DeltaManifest{Format: "cinderlock.delta.v1", BaseDigest: base.Digest, TargetDigest: target.Digest, Changed: []spec.Descriptor{}}
	if err := os.Mkdir(outDir, 0700); err != nil {
		return m, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(outDir)
		}
	}()
	baseFiles := map[string]int64{}
	for _, d := range base.Index.Payloads {
		baseFiles[d.Digest] = d.Size
	}
	for _, d := range target.Index.Payloads {
		if size, ok := baseFiles[d.Digest]; ok && size == d.Size {
			continue
		}
		if err := bundle.VerifyBlob(ctx, target.Root, d.Digest, d.Size); err != nil {
			return m, err
		}
		p, _ := bundle.BlobPath(target.Root, d.Digest)
		if err := copyFile(ctx, p, filepath.Join(outDir, filepath.FromSlash(d.Path)), d.Size); err != nil {
			return m, err
		}
		m.Changed = append(m.Changed, d)
	}
	index, err := readBounded(filepath.Join(target.Root, bundle.IndexName), bundle.MaxMetadataBytes)
	if err != nil {
		return m, err
	}
	if spec.Hash(index) != target.Digest {
		return m, errors.New("target metadata changed after verification")
	}
	if err := spec.WriteBytes(filepath.Join(outDir, bundle.IndexName), index); err != nil {
		return m, err
	}
	entries, err := os.ReadDir(filepath.Join(target.Root, "signatures"))
	if err != nil {
		return m, err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return m, errors.New("invalid target signature entry")
		}
		b, err := readBounded(filepath.Join(target.Root, "signatures", entry.Name()), 16384)
		if err != nil {
			return m, err
		}
		if err := spec.WriteBytes(filepath.Join(outDir, "signatures", entry.Name()), b); err != nil {
			return m, err
		}
	}
	b, err := spec.Canonical(m)
	if err != nil {
		return m, err
	}
	if err := spec.WriteBytes(filepath.Join(outDir, DeltaName), b); err != nil {
		return m, err
	}
	complete = true
	return m, nil
}

// ReconstructDelta publishes only after the entire target bundle passes its original trust and payload checks.
func ReconstructDelta(ctx context.Context, dir string, base *bundle.Verified, policy spec.TrustPolicy, out string) (DeltaManifest, error) {
	var m DeltaManifest
	b, err := readBounded(filepath.Join(dir, DeltaName), bundle.MaxMetadataBytes)
	if err != nil {
		return m, err
	}
	if err := bundle.DecodeJSON(b, &m); err != nil {
		return m, err
	}
	if m.Format != "cinderlock.delta.v1" || m.BaseDigest != base.Digest || !bundle.ValidDigest(m.TargetDigest) || len(m.Changed) > bundle.MaxMembers {
		return m, errors.New("delta base, format, or target identity is invalid")
	}
	indexBytes, err := readBounded(filepath.Join(dir, bundle.IndexName), bundle.MaxMetadataBytes)
	if err != nil {
		return m, err
	}
	if spec.Hash(indexBytes) != m.TargetDigest {
		return m, errors.New("delta target metadata identity mismatch")
	}
	var index spec.BundleIndex
	if err := bundle.DecodeJSON(indexBytes, &index); err != nil {
		return m, err
	}
	if len(index.Payloads) > bundle.MaxMembers {
		return m, errors.New("target inventory exceeds limit")
	}
	expected := map[string]bool{DeltaName: true, bundle.IndexName: true}
	changed := map[string]spec.Descriptor{}
	target := map[string]spec.Descriptor{}
	var total int64
	for _, d := range index.Payloads {
		if !bundle.ValidDigest(d.Digest) || d.Path != "blobs/sha256/"+d.Digest[7:] || d.Size < 0 || d.Size > bundle.MaxPayloadBytes-total {
			return m, errors.New("invalid target payload")
		}
		if _, ok := target[d.Digest]; ok {
			return m, errors.New("duplicate target payload")
		}
		target[d.Digest] = d
		total += d.Size
	}
	for _, d := range m.Changed {
		if t, ok := target[d.Digest]; !ok || d != t {
			return m, errors.New("delta object is not in target inventory")
		}
		if _, ok := changed[d.Digest]; ok {
			return m, errors.New("duplicate delta object")
		}
		changed[d.Digest] = d
		expected[d.Path] = true
		if err := bundle.VerifyBlob(ctx, dir, d.Digest, d.Size); err != nil {
			return m, err
		}
	}
	baseFiles := map[string]int64{}
	for _, d := range base.Index.Payloads {
		baseFiles[d.Digest] = d.Size
	}
	for _, d := range index.Payloads {
		if _, ok := changed[d.Digest]; ok {
			continue
		}
		if size, ok := baseFiles[d.Digest]; !ok || size != d.Size {
			return m, fmt.Errorf("recipient base lacks required object %s", d.Digest)
		}
		if err := bundle.VerifyBlob(ctx, base.Root, d.Digest, d.Size); err != nil {
			return m, err
		}
	}
	signatures := map[string][]byte{}
	entries, err := os.ReadDir(filepath.Join(dir, "signatures"))
	if err != nil {
		return m, err
	}
	if len(entries) == 0 || len(entries) > 256 {
		return m, errors.New("delta signatures absent or excessive")
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".sig") || strings.ContainsAny(entry.Name(), "/\\") {
			return m, errors.New("invalid signature path")
		}
		name := "signatures/" + entry.Name()
		b, err := readBounded(filepath.Join(dir, filepath.FromSlash(name)), 16384)
		if err != nil {
			return m, err
		}
		signatures[name] = b
		expected[name] = true
	}
	count := 0
	err = filepath.WalkDir(dir, func(p string, entry fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() {
			return nil
		}
		count++
		if count > bundle.MaxMembers {
			return errors.New("delta member limit exceeded")
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(dir, p)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || !expected[filepath.ToSlash(rel)] {
			return errors.New("delta contains unlisted or linked content")
		}
		return nil
	})
	if err != nil {
		return m, err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		return m, err
	}
	f, err := os.CreateTemp(filepath.Dir(out), ".cinderlock-reconstruct-")
	if err != nil {
		return m, err
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	tw := tar.NewWriter(f)
	write := func(name string, size int64, r io.Reader) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: size, Mode: 0644, Typeflag: tar.TypeReg, Format: tar.FormatGNU}); err != nil {
			return err
		}
		_, err := io.CopyN(tw, &contextReader{ctx: ctx, r: r}, size)
		return err
	}
	if err := write(bundle.IndexName, int64(len(indexBytes)), bytes.NewReader(indexBytes)); err != nil {
		return m, err
	}
	for _, entry := range entries {
		name := "signatures/" + entry.Name()
		b := signatures[name]
		if err := write(name, int64(len(b)), bytes.NewReader(b)); err != nil {
			return m, err
		}
	}
	for _, d := range index.Payloads {
		root := base.Root
		if _, ok := changed[d.Digest]; ok {
			root = dir
		}
		p, _ := bundle.BlobPath(root, d.Digest)
		in, err := os.Open(p)
		if err != nil {
			return m, err
		}
		err = write(d.Path, d.Size, in)
		in.Close()
		if err != nil {
			return m, err
		}
	}
	if err := tw.Close(); err != nil {
		return m, err
	}
	if err := f.Sync(); err != nil {
		return m, err
	}
	if err := f.Close(); err != nil {
		return m, err
	}
	v, err := bundle.Verify(ctx, f.Name(), policy)
	if err != nil {
		return m, err
	}
	if v.Digest != m.TargetDigest {
		v.Close()
		return m, errors.New("reconstructed target identity mismatch")
	}
	v.Close()
	if err := os.Link(f.Name(), out); err != nil {
		return m, err
	}
	return m, nil
}

func readBounded(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, errors.New("metadata file type/size is invalid")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("metadata exceeds limit")
	}
	return b, nil
}
func copyFile(ctx context.Context, source, dest string, size int64) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.CopyN(out, &contextReader{ctx: ctx, r: in}, size)
	if err == nil {
		err = out.Sync()
	}
	return err
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
