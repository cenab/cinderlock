package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
)

const SignatureDomain = spec.BundleDomain + "\x00"

func GenerateKey(privatePath, publicPath string) error {
	if privatePath == publicPath {
		return errors.New("private and public key paths must differ")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := writeExclusive(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	if err := writeExclusive(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0644); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}

func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := readPrivateFile(path, 16384)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("expected one PKCS8 PRIVATE KEY PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not Ed25519")
	}
	return priv, nil
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &spec.Error{Code: 16, Message: "cannot open admitted private input: " + err.Error(), Cause: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (info.Mode().Perm() != 0600 && info.Mode().Perm() != 0400) {
		return nil, spec.Err(16, "private input must be a regular non-symlink file with mode 0600 or 0400")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("private input file exceeds limit")
	}
	return b, nil
}

func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	if block, rest := pem.Decode([]byte(value)); block != nil {
		if len(rest) != 0 || block.Type != "PUBLIC KEY" {
			return nil, errors.New("expected one PUBLIC KEY PEM block")
		}
		v, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := v.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("public key is not Ed25519")
		}
		return key, nil
	}
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("expected base64 Ed25519 public key or PUBLIC KEY PEM")
	}
	return ed25519.PublicKey(b), nil
}

func Sign(data []byte, keyID string, key ed25519.PrivateKey) (spec.Signature, error) {
	if keyID == "" || len(key) != ed25519.PrivateKeySize {
		return spec.Signature{}, errors.New("key ID and Ed25519 private key are required")
	}
	s := ed25519.Sign(key, append([]byte(SignatureDomain), data...))
	return spec.Signature{KeyID: keyID, Algorithm: "Ed25519", Signature: base64.StdEncoding.EncodeToString(s)}, nil
}

func VerifySignature(data []byte, signature spec.Signature, key ed25519.PublicKey) error {
	if signature.Algorithm != "Ed25519" || len(key) != ed25519.PublicKeySize {
		return errors.New("unsupported signature algorithm or key")
	}
	sig, err := base64.StdEncoding.DecodeString(signature.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("malformed Ed25519 signature")
	}
	if !ed25519.Verify(key, append([]byte(SignatureDomain), data...), sig) {
		return fmt.Errorf("signature verification failed for key %q", signature.KeyID)
	}
	return nil
}

func writeExclusive(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = f.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}
