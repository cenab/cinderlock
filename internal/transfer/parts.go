package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

type Part struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}
type Manifest struct {
	Format string `json:"format"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Parts  []Part `json:"parts"`
}

// Split creates independently hashable transport units; signature verification remains a separate bundle gate.
func Split(ctx context.Context, source, outputDir string, partSize int64) (Manifest, error) {
	var m Manifest
	if partSize < 1 || partSize > bundle.MaxPayloadBytes {
		return m, errors.New("part size is outside supported limits")
	}
	f, err := os.Open(source)
	if err != nil {
		return m, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return m, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > bundle.MaxPayloadBytes {
		return m, errors.New("invalid source file")
	}
	if err := os.Mkdir(outputDir, 0700); err != nil {
		return m, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(outputDir)
		}
	}()
	m.Format = "cinderlock.multipart.v1"
	m.Size = info.Size()
	whole := sha256.New()
	remaining := info.Size()
	for i := 0; remaining > 0; i++ {
		if err := ctx.Err(); err != nil {
			return m, err
		}
		if i >= 100000 {
			return m, errors.New("too many transport parts")
		}
		p := Part{Name: fmt.Sprintf("part-%06d", i), Size: min(partSize, remaining)}
		out, err := os.OpenFile(filepath.Join(outputDir, p.Name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return m, err
		}
		h := sha256.New()
		_, err = io.CopyN(io.MultiWriter(out, h, whole), &contextReader{ctx: ctx, r: f}, p.Size)
		if err == nil {
			err = out.Sync()
		}
		closeErr := out.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return m, err
		}
		p.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
		m.Parts = append(m.Parts, p)
		remaining -= p.Size
	}
	m.Digest = "sha256:" + hex.EncodeToString(whole.Sum(nil))
	b, err := spec.Canonical(m)
	if err != nil {
		return m, err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "parts.json"), b, 0600); err != nil {
		return m, err
	}
	complete = true
	return m, nil
}

// Join only verifies transport integrity; callers must authenticate the reconstructed bundle before use.
func Join(ctx context.Context, dir, output string) (Manifest, error) {
	var m Manifest
	b, err := readBounded(filepath.Join(dir, "parts.json"), bundle.MaxMetadataBytes)
	if err != nil {
		return m, err
	}
	if len(b) > int(bundle.MaxMetadataBytes) {
		return m, errors.New("multipart manifest exceeds limit")
	}
	if err := bundle.DecodeJSON(b, &m); err != nil {
		return m, err
	}
	if m.Format != "cinderlock.multipart.v1" || !bundle.ValidDigest(m.Digest) || m.Size < 1 || m.Size > bundle.MaxPayloadBytes || len(m.Parts) == 0 || len(m.Parts) > 100000 {
		return m, errors.New("invalid multipart manifest")
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return m, err
	}
	complete := false
	defer func() {
		_ = f.Close()
		if !complete {
			_ = os.Remove(output)
		}
	}()
	whole := sha256.New()
	total := int64(0)
	for i, p := range m.Parts {
		if err := ctx.Err(); err != nil {
			return m, err
		}
		if p.Name != fmt.Sprintf("part-%06d", i) || !bundle.ValidDigest(p.Digest) || p.Size < 1 || p.Size > m.Size-total {
			return m, errors.New("invalid multipart descriptor")
		}
		path := filepath.Join(dir, p.Name)
		info, err := os.Lstat(path)
		if err != nil {
			return m, err
		}
		if !info.Mode().IsRegular() || info.Size() != p.Size {
			return m, fmt.Errorf("part %s size/type mismatch", p.Name)
		}
		in, err := os.Open(path)
		if err != nil {
			return m, err
		}
		h := sha256.New()
		_, err = io.CopyN(io.MultiWriter(f, whole, h), &contextReader{ctx: ctx, r: in}, p.Size)
		closeErr := in.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return m, err
		}
		if "sha256:"+hex.EncodeToString(h.Sum(nil)) != p.Digest {
			return m, fmt.Errorf("part %s digest mismatch", p.Name)
		}
		total += p.Size
	}
	if total != m.Size || "sha256:"+hex.EncodeToString(whole.Sum(nil)) != m.Digest {
		return m, errors.New("reconstructed bundle digest mismatch")
	}
	if err := f.Sync(); err != nil {
		return m, err
	}
	if err := f.Close(); err != nil {
		return m, err
	}
	complete = true
	return m, nil
}
