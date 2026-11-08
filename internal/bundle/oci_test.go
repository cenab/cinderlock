package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ociSpec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote/auth"
)

func imageFixture(t *testing.T) (string, ociSpec.Descriptor) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	store, err := oci.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	push := func(media string, b []byte) ociSpec.Descriptor {
		d := ociSpec.Descriptor{MediaType: media, Digest: digest.FromBytes(b), Size: int64(len(b))}
		if err := store.Push(ctx, d, bytes.NewReader(b)); err != nil {
			t.Fatal(err)
		}
		return d
	}
	config := push(ociSpec.MediaTypeImageConfig, []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`))
	layer := push(ociSpec.MediaTypeImageLayer, []byte("unit-test image layer content"))
	m := ociSpec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ociSpec.MediaTypeImageManifest, Config: config, Layers: []ociSpec.Descriptor{layer}}
	b, err := spec.Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	root := push(ociSpec.MediaTypeImageManifest, b)
	if err := store.Tag(ctx, root, "demo"); err != nil {
		t.Fatal(err)
	}
	return dir, root
}

func TestOCIClosureAndCorruption(t *testing.T) {
	ctx := context.Background()
	source, root := imageFixture(t)
	cache := filepath.Join(t.TempDir(), "cache")
	a, err := lockImageWithOptions(ctx, spec.Asset{ID: "inference", Type: "image", Source: "oci:" + source + "#demo", Platform: "linux/amd64"}, filepath.Dir(source), cache, RegistryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != root.Digest.String() || len(a.Files) != 3 {
		t.Fatalf("graph incomplete: %+v", a)
	}
	store, err := oci.New(cache)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := imageGraph(ctx, store, root); err != nil {
		t.Fatal(err)
	}
	for _, f := range a.Files {
		if f.Digest != a.Digest {
			p, _ := BlobPath(cache, f.Digest)
			if err := os.Chmod(p, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("damaged"), 0600); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if _, err := imageGraph(ctx, store, root); err == nil {
		t.Fatal("corrupt transitive OCI child accepted")
	}
}

func TestOCIRegistryRoundTrip(t *testing.T) {
	registry := os.Getenv("CINDERLOCK_TEST_REGISTRY")
	if registry == "" {
		t.Skip("set CINDERLOCK_TEST_REGISTRY to an isolated HTTP registry host:port")
	}
	ctx := context.Background()
	source, _ := imageFixture(t)
	cache := filepath.Join(t.TempDir(), "cache")
	a, err := lockImageWithOptions(ctx, spec.Asset{ID: "test-image", Type: "image", Source: "oci:" + source + "#demo"}, filepath.Dir(source), cache, RegistryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v := &Verified{Root: cache, Index: spec.BundleIndex{Lock: spec.ReleaseLock{Assets: []spec.LockedAsset{a}}}}
	dest, err := ImportImage(ctx, v, a.ID, registry+"/cinderlock-bundle-test", RegistryOptions{PlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if dest != registry+"/cinderlock-bundle-test@"+a.Digest {
		t.Fatal("destination identity changed")
	}
}

func TestOCIConflictingDescriptorsAndForeignURLsRejected(t *testing.T) {
	ctx := context.Background()
	source, root := imageFixture(t)
	store, err := oci.New(source)
	if err != nil {
		t.Fatal(err)
	}
	r, err := store.Fetch(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	var original ociSpec.Manifest
	if err := json.Unmarshal(b, &original); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"conflicting descriptor", "foreign URL"} {
		t.Run(mode, func(t *testing.T) {
			m := original
			m.Layers = append([]ociSpec.Descriptor{}, original.Layers...)
			if mode == "foreign URL" {
				m.Layers[0].URLs = []string{"https://external.example/layer"}
			} else {
				d := m.Layers[0]
				d.Size++
				m.Layers = append(m.Layers, d)
			}
			b, err := spec.Canonical(m)
			if err != nil {
				t.Fatal(err)
			}
			d := ociSpec.Descriptor{MediaType: ociSpec.MediaTypeImageManifest, Digest: digest.FromBytes(b), Size: int64(len(b))}
			if err := store.Push(ctx, d, bytes.NewReader(b)); err != nil {
				t.Fatal(err)
			}
			if _, err := imageGraph(ctx, store, d); err == nil {
				t.Fatal("unsafe OCI graph accepted")
			}
		})
	}
	if _, err := lockImageWithOptions(ctx, spec.Asset{ID: "wrong-platform", Type: "image", Source: "oci:" + source + "#demo", Platform: "linux/arm64"}, filepath.Dir(source), filepath.Join(t.TempDir(), "cache"), RegistryOptions{}); err == nil {
		t.Fatal("declared platform did not match actual image config")
	}
}

func TestRegistryRedirectCredentialScope(t *testing.T) {
	client, err := registryClient("approved.example/repo", RegistryOptions{Username: "operator", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	httpClient := client.Client.(*auth.Client).Client
	origin, _ := http.NewRequest(http.MethodGet, "https://approved.example/v2/repo/blobs/digest", nil)
	redirect, _ := http.NewRequest(http.MethodGet, "https://cdn.example/blob", nil)
	redirect.Header.Set("Authorization", "Basic secret")
	redirect.Header.Set("Cookie", "secret")
	if err := httpClient.CheckRedirect(redirect, []*http.Request{origin}); err == nil {
		t.Fatal("unadmitted redirect host accepted")
	}
	client, err = registryClient("approved.example/repo", RegistryOptions{Username: "operator", Password: "secret", AllowedRedirectHosts: []string{"cdn.example"}})
	if err != nil {
		t.Fatal(err)
	}
	httpClient = client.Client.(*auth.Client).Client
	if err := httpClient.CheckRedirect(redirect, []*http.Request{origin}); err != nil {
		t.Fatal(err)
	}
	if redirect.Header.Get("Authorization") != "" || redirect.Header.Get("Cookie") != "" {
		t.Fatal("credentials forwarded to another host")
	}
	post, _ := http.NewRequest(http.MethodPost, "https://cdn.example/token", strings.NewReader("password=secret"))
	if err := httpClient.CheckRedirect(post, []*http.Request{origin}); err == nil {
		t.Fatal("credential-bearing request body redirected across hosts")
	}
}
