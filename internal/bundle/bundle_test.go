package bundle

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

type fixture struct {
	dir, cache, archive, key string
	lock                     spec.ReleaseLock
	policy                   spec.TrustPolicy
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	key := filepath.Join(dir, "key.pem")
	public := filepath.Join(dir, "public.pem")
	if err := GenerateKey(key, public); err != nil {
		t.Fatal(err)
	}
	priv, err := ReadPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	policy := spec.TrustPolicy{Header: spec.NewHeader("TrustPolicy"), Spec: spec.TrustSpec{Epoch: 1, Keys: []spec.TrustedKey{{ID: "release", PublicKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)), Applications: []string{"demo"}, Channels: []string{"stable"}, Roles: []string{"release"}}}}}
	if err := os.WriteFile(filepath.Join(dir, "chart.tgz"), []byte("unit-test chart transport bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "model"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"weights.bin": "test-weights", "tokenizer.json": "{}"} {
		if err := os.WriteFile(filepath.Join(dir, "model", name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := spec.Release{Header: spec.NewHeader("Release"), Spec: spec.ReleaseSpec{Profile: "lab", Deployment: spec.Deployment{Type: "helm", Chart: "chart.tgz"}, Assets: []spec.Asset{{ID: "model", Type: "model-tree", Source: "model"}}, Operations: []spec.Operation{{ID: "deploy", Type: "helm", Idempotent: true}}, Checks: []spec.Check{{ID: "health", Type: "http", Domain: "workflow", Required: true, URL: "http://api/health", ExpectedStatus: 200}}, RequiredChecks: []string{"health"}, Transitions: []spec.Transition{{ID: "from-1", FromRelease: "1", Operations: []string{"deploy"}, Recovery: "previous"}}, Recovery: []spec.Recovery{{ID: "previous", ToRelease: "1", Operations: []spec.Operation{{ID: "previous-deploy", Type: "helm", Idempotent: true}}}}}}
	r.Metadata = spec.Metadata{Application: "demo", Version: "2", Channel: "stable", Sequence: 2}
	p := filepath.Join(dir, "release.json")
	if err := spec.Write(p, r); err != nil {
		t.Fatal(err)
	}
	lock, err := Lock(context.Background(), p, cache)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "release.cinder")
	if err := Build(context.Background(), lock, cache, archive, key, "release"); err != nil {
		t.Fatal(err)
	}
	return fixture{dir: dir, cache: cache, archive: archive, key: key, lock: lock, policy: policy}
}

func TestBuildVerifyMaterializeAndDeterminism(t *testing.T) {
	f := newFixture(t)
	v, err := Verify(context.Background(), f.archive, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if !ValidDigest(v.Digest) {
		t.Fatal("missing identity")
	}
	if v.Index.Inventory == nil {
		t.Fatal("signed component inventory is missing")
	}
	inventoryBytes, err := InventoryBytes(v)
	if err != nil {
		t.Fatal(err)
	}
	var inventory BOM
	if err := DecodeJSON(inventoryBytes, &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Compositions[0].Aggregate != "incomplete" {
		t.Fatal("inventory overstated coverage")
	}
	p, err := Materialize(v, "model", filepath.Join(f.dir, "materialized"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(p, "weights.bin"))
	if err != nil || string(b) != "test-weights" {
		t.Fatal("materialized content mismatch", err)
	}
	second := filepath.Join(f.dir, "second.cinder")
	if err := Build(context.Background(), f.lock, f.cache, second, f.key, "release"); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(f.archive)
	b, _ = os.ReadFile(second)
	if !bytes.Equal(a, b) {
		t.Fatal("same locked content and signer produced different archive bytes")
	}
	if err := Build(context.Background(), f.lock, f.cache, second, f.key, "release"); err == nil {
		t.Fatal("overwrote output")
	}
}

type tarEntry struct {
	h tar.Header
	b []byte
}

func rewrite(t *testing.T, f fixture, transform func([]tarEntry) []tarEntry) string {
	t.Helper()
	in, err := os.Open(f.archive)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	tr := tar.NewReader(in)
	var entries []tarEntry
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, tarEntry{h: *h, b: b})
	}
	entries = transform(entries)
	p := filepath.Join(t.TempDir(), "mutated.cinder")
	out, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(out)
	for _, e := range entries {
		e.h.Size = int64(len(e.b))
		if e.h.Typeflag != tar.TypeReg {
			e.h.Size = 0
		}
		if err := tw.WriteHeader(&e.h); err != nil {
			t.Fatal(err)
		}
		if len(e.b) > 0 {
			if _, err := tw.Write(e.b); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHostileArchivesRejected(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func([]tarEntry) []tarEntry{
		"corrupt payload": func(e []tarEntry) []tarEntry {
			for n := range e {
				if strings.HasPrefix(e[n].h.Name, "blobs/") {
					e[n].b[0] ^= 0xff
					break
				}
			}
			return e
		},
		"duplicate index": func(e []tarEntry) []tarEntry { return append(e, e[0]) },
		"parent traversal": func(e []tarEntry) []tarEntry {
			return append(e, tarEntry{h: tar.Header{Name: "../escaped", Typeflag: tar.TypeReg, Format: tar.FormatGNU}, b: []byte("x")})
		},
		"symlink": func(e []tarEntry) []tarEntry {
			return append(e, tarEntry{h: tar.Header{Name: "signatures/evil.sig", Typeflag: tar.TypeSymlink, Linkname: "../../escaped", Format: tar.FormatGNU}})
		},
		"unindexed payload": func(e []tarEntry) []tarEntry {
			b := []byte("unindexed")
			return append(e, tarEntry{h: tar.Header{Name: "blobs/sha256/" + spec.Hash(b)[7:], Typeflag: tar.TypeReg, Format: tar.FormatGNU}, b: b})
		},
		"missing payload": func(e []tarEntry) []tarEntry { return e[:len(e)-1] },
		"unknown member": func(e []tarEntry) []tarEntry {
			return append(e, tarEntry{h: tar.Header{Name: "unexpected.json", Typeflag: tar.TypeReg, Format: tar.FormatGNU}, b: []byte("{}")})
		},
	}
	for name, transform := range cases {
		t.Run(name, func(t *testing.T) {
			p := rewrite(t, f, transform)
			if v, err := Verify(context.Background(), p, f.policy); err == nil {
				v.Close()
				t.Fatal("hostile archive accepted")
			}
		})
	}
	b, _ := os.ReadFile(f.archive)
	for _, test := range []struct {
		name string
		b    []byte
	}{{"truncation", b[:len(b)-700]}, {"trailing data", append(b, 1)}} {
		t.Run(test.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bad.cinder")
			os.WriteFile(p, test.b, 0600)
			if v, err := Verify(context.Background(), p, f.policy); err == nil {
				v.Close()
				t.Fatal("malformed transport accepted")
			}
		})
	}
}

func TestTrustScopeRevocationAndSequence(t *testing.T) {
	f := newFixture(t)
	for _, mode := range []string{"application", "channel", "revoked", "role", "sequence"} {
		t.Run(mode, func(t *testing.T) {
			p := f.policy
			p.Spec.Keys = append([]spec.TrustedKey{}, f.policy.Spec.Keys...)
			switch mode {
			case "application":
				p.Spec.Keys[0].Applications = []string{"other"}
			case "channel":
				p.Spec.Keys[0].Channels = []string{"other"}
			case "revoked":
				p.Spec.Keys[0].Revoked = true
			case "role":
				p.Spec.Keys[0].Roles = []string{"approval"}
			case "sequence":
				p.Spec.MinSequence = map[string]int64{"demo/stable": 3}
			}
			if v, err := Verify(context.Background(), f.archive, p); err == nil {
				v.Close()
				t.Fatal("unauthorized release accepted")
			}
		})
	}
}

func TestSignedNoncanonicalAndDuplicateKeysRejected(t *testing.T) {
	f := newFixture(t)
	key, err := ReadPrivateKey(f.key)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"whitespace", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			p := rewrite(t, f, func(entries []tarEntry) []tarEntry {
				for n := range entries {
					if entries[n].h.Name == IndexName {
						if mode == "whitespace" {
							entries[n].b = append([]byte(" "), entries[n].b...)
						} else {
							entries[n].b = append([]byte(`{"domain":"different",`), entries[n].b[1:]...)
						}
						s, _ := Sign(entries[n].b, "release", key)
						b, _ := spec.Canonical(s)
						for j := range entries {
							if entries[j].h.Name == "signatures/release.sig" {
								entries[j].b = b
							}
						}
						break
					}
				}
				return entries
			})
			if v, err := Verify(context.Background(), p, f.policy); err == nil {
				v.Close()
				t.Fatal("malformed signed metadata accepted")
			}
		})
	}
}

func TestWorkspaceEscapeAndCorruptCache(t *testing.T) {
	f := newFixture(t)
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("secret"), 0600)
	if err := os.Symlink(outside, filepath.Join(f.dir, "model", "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(context.Background(), filepath.Join(f.dir, "release.json"), f.cache); err == nil {
		t.Fatal("workspace symlink escape accepted")
	}
	d := f.lock.Assets[0].Files[0].Digest
	p, _ := BlobPath(f.cache, d)
	os.WriteFile(p, []byte("corrupt"), 0600)
	out := filepath.Join(f.dir, "bad.cinder")
	if err := Build(context.Background(), f.lock, f.cache, out, f.key, "release"); err == nil {
		t.Fatal("corrupted cached input accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("failed build left an output")
	}
}

func FuzzStrictSignedJSON(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, b []byte) { var v map[string]any; _ = strictJSON(b, &v, true) })
}

func TestPrivateSigningKeyAndSelfReferentialInputRejected(t *testing.T) {
	f := newFixture(t)
	var r spec.Release
	if err := spec.Read(filepath.Join(f.dir, "release.json"), &r); err != nil {
		t.Fatal(err)
	}
	r.Spec.Assets = append(r.Spec.Assets, spec.Asset{ID: "accidental-key", Type: "file", Source: "key.pem"})
	b, err := spec.Canonical(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "release.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := Lock(context.Background(), filepath.Join(f.dir, "release.json"), f.cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := Build(context.Background(), lock, f.cache, filepath.Join(f.dir, "leak.cinder"), f.key, "release"); err == nil {
		t.Fatal("signing private key was packaged")
	}
	if _, err := lockFilesWithOptions(context.Background(), spec.Asset{ID: "self", Type: "file-tree", Source: "."}, f.dir, f.cache, RegistryOptions{}); err == nil {
		t.Fatal("self-referential input/cache accepted")
	}
}

func TestZeroBytePayloadAndDirectoryTransport(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(filepath.Join(f.dir, "model", "weights.bin"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := Lock(context.Background(), filepath.Join(f.dir, "release.json"), f.cache)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(f.dir, "zero.cinder")
	if err := Build(context.Background(), lock, f.cache, out, f.key, "release"); err != nil {
		t.Fatal(err)
	}
	v, err := Verify(context.Background(), out, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	fromDirectory, err := Verify(context.Background(), v.Root, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	defer fromDirectory.Close()
	if fromDirectory.Digest != v.Digest {
		t.Fatal("directory transport identity changed")
	}
}

func TestPrivateKeyPermissionsAndLinks(t *testing.T) {
	f := newFixture(t)
	if err := os.Chmod(f.key, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateKey(f.key); err == nil {
		t.Fatal("group/world-readable private key accepted")
	}
	if err := os.Chmod(f.key, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.dir, "linked-key.pem")
	if err := os.Symlink(f.key, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateKey(link); err == nil {
		t.Fatal("private key symlink accepted")
	}
}

func TestArtifactRedirectScope(t *testing.T) {
	client, err := sourceHTTPClient("https://approved.example", RegistryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := http.NewRequest(http.MethodGet, "https://approved.example/artifact", nil)
	same, _ := http.NewRequest(http.MethodGet, "https://approved.example/next", nil)
	if err := client.CheckRedirect(same, []*http.Request{origin}); err != nil {
		t.Fatal(err)
	}
	other, _ := http.NewRequest(http.MethodGet, "https://internal.example/admin", nil)
	if err := client.CheckRedirect(other, []*http.Request{origin}); err == nil {
		t.Fatal("cross-host source redirect accepted")
	}
}
