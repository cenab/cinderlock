package transfer

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMultipartRoundTripAndCorruption(t *testing.T) {
	d := t.TempDir()
	data := bytes.Repeat([]byte("offline artifacts\x00"), 1000)
	source := filepath.Join(d, "release.cinder")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	parts := filepath.Join(d, "parts")
	m, err := Split(context.Background(), source, parts, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Parts) < 2 {
		t.Fatal("fixture did not split")
	}
	out := filepath.Join(d, "joined.cinder")
	got, err := Join(context.Background(), parts, out)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if !bytes.Equal(data, b) || got.Digest != m.Digest {
		t.Fatal("transport bytes changed")
	}
	if _, err := Join(context.Background(), parts, out); err == nil {
		t.Fatal("output overwritten")
	}
	p := filepath.Join(parts, m.Parts[0].Name)
	b, _ = os.ReadFile(p)
	b[0] ^= 0xff
	os.WriteFile(p, b, 0600)
	bad := filepath.Join(d, "bad.cinder")
	if _, err := Join(context.Background(), parts, bad); err == nil {
		t.Fatal("corrupt part accepted")
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("corrupt join output retained")
	}
}

func TestMultipartMissingPartAndDuplicateMetadata(t *testing.T) {
	d := t.TempDir()
	source := filepath.Join(d, "source")
	os.WriteFile(source, []byte("abcdefgh"), 0600)
	parts := filepath.Join(d, "parts")
	m, err := Split(context.Background(), source, parts, 4)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(parts, m.Parts[0].Name))
	if _, err := Join(context.Background(), parts, filepath.Join(d, "out")); err == nil {
		t.Fatal("missing part accepted")
	}
	if err := os.WriteFile(filepath.Join(parts, "parts.json"), []byte(`{"format":"cinderlock.multipart.v1","format":"other"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Join(context.Background(), parts, filepath.Join(d, "out")); err == nil {
		t.Fatal("duplicate manifest keys accepted")
	}
}
