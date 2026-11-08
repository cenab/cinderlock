package engine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
)

func (e *Engine) secretFingerprint(secret *corev1.Secret, data map[string][]byte) (string, error) {
	body, err := spec.Canonical(struct {
		Namespace, Name, UID string
		Type                 corev1.SecretType
		Data                 map[string][]byte
	}{secret.Namespace, secret.Name, string(secret.UID), secret.Type, data})
	if err != nil {
		return "", errors.New("cannot encode private Secret binding")
	}
	value, err := e.privateFingerprint(append([]byte("cinderlock.inspection-secret.v1\x00"), body...))
	if err != nil {
		return "", errors.New("cannot fingerprint private Secret binding")
	}
	return value, nil
}

func (e *Engine) privateFileFingerprint(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("cannot open private Secret file: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return "", errors.New("Secret file must be a private regular file of at most one MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return "", errors.New("cannot capture bounded private Secret file")
	}
	return e.privateFingerprint(append([]byte("cinderlock.inspection-secret-file.v1\x00"), data...))
}

func (e *Engine) privateFingerprint(data []byte) (string, error) {
	if err := os.MkdirAll(e.StateDir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(e.StateDir, "configuration-fingerprint.key")
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return "", err
		}
		if err := spec.WriteBytes(path, key); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return "", err
			}
			key, err = os.ReadFile(path)
			if err != nil {
				return "", err
			}
		}
	} else if err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", errors.New("invalid local fingerprint key")
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return "hmac-sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
