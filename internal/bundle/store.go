package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const MaxMetadataBytes int64 = 8 << 20
const MaxPayloadBytes int64 = 16 << 40
const MaxMembers = 1000000

func ValidDigest(d string) bool {
	if len(d) != 71 || !strings.HasPrefix(d, "sha256:") {
		return false
	}
	for _, c := range d[7:] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func BlobPath(root, digest string) (string, error) {
	if !ValidDigest(digest) {
		return "", fmt.Errorf("invalid SHA-256 digest %q", digest)
	}
	return filepath.Join(root, "blobs", "sha256", digest[7:]), nil
}

func Store(ctx context.Context, root string, reader io.Reader, max int64) (string, int64, error) {
	if max <= 0 || max > MaxPayloadBytes {
		return "", 0, errors.New("invalid object size limit")
	}
	dir := filepath.Join(root, "blobs", "sha256")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", 0, err
	}
	f, err := os.CreateTemp(dir, ".partial-")
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), &contextReader{ctx: ctx, r: io.LimitReader(reader, max+1)})
	if err != nil {
		return "", n, err
	}
	if n > max {
		return "", n, errors.New("object exceeds configured size limit")
	}
	digest := "sha256:" + hex.EncodeToString(h.Sum(nil))
	dest, _ := BlobPath(root, digest)
	if err := f.Sync(); err != nil {
		return "", n, err
	}
	if err := f.Close(); err != nil {
		return "", n, err
	}
	if err := os.Link(f.Name(), dest); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", n, err
		}
		if err := VerifyBlob(ctx, root, digest, n); err != nil {
			return "", n, err
		}
	}
	return digest, n, nil
}

func VerifyBlob(ctx context.Context, root, digest string, size int64) error {
	p, err := BlobPath(root, digest)
	if err != nil {
		return err
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != size || size < 0 || size > MaxPayloadBytes {
		return fmt.Errorf("blob %s size/type mismatch", digest)
	}
	h := sha256.New()
	if _, err := io.Copy(h, &contextReader{ctx: ctx, r: f}); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != digest[7:] {
		return fmt.Errorf("blob %s digest mismatch", digest)
	}
	return nil
}

func safeMember(name string) bool {
	if name == "" || len(name) > 512 || !utf8.ValidString(name) || strings.ContainsAny(name, "\\\x00:") || strings.HasPrefix(name, "/") || path.Clean(name) != name {
		return false
	}
	for _, p := range strings.Split(name, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	for _, c := range name {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
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
