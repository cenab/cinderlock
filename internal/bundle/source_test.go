package bundle

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	"oras.land/oras-go/v2/content/oci"
)

func TestRegistryBearerRealmCannotAcquireOriginCredentials(t *testing.T) {
	for _, scenario := range []string{"different-https-host", "different-http-host", "https-downgrade", "cdn-is-not-auth"} {
		t.Run(scenario, func(t *testing.T) {
			var requests atomic.Int64
			var credentials atomic.Bool
			endpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				user, password, ok := r.BasicAuth()
				if ok && user == "origin-user" && password == "origin-password" {
					credentials.Store(true)
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			})
			var realm *httptest.Server
			if scenario == "different-http-host" || scenario == "https-downgrade" {
				realm = httptest.NewServer(endpoint)
			} else {
				realm = httptest.NewTLSServer(endpoint)
			}
			defer realm.Close()
			challenge := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm.URL+`/token?private=realm-query-secret",service="registry"`)
				w.WriteHeader(http.StatusUnauthorized)
			})
			var registry *httptest.Server
			if scenario == "different-http-host" {
				registry = httptest.NewServer(challenge)
			} else {
				registry = httptest.NewTLSServer(challenge)
			}
			defer registry.Close()
			host := strings.TrimPrefix(strings.TrimPrefix(registry.URL, "https://"), "http://")
			dir := t.TempDir()
			opts := RegistryOptions{PlainHTTP: scenario == "different-http-host", Username: "origin-user", Password: "origin-password"}
			if registry.TLS != nil {
				opts.CAFile = filepath.Join(dir, "source-ca.pem")
				if err := os.WriteFile(opts.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw}), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "cdn-is-not-auth" {
				opts.AllowedRedirectHosts = []string{strings.TrimPrefix(realm.URL, "https://")}
			}
			_, err := lockImageWithOptions(context.Background(), spec.Asset{ID: "private", Type: "image", Source: host + "/private:latest"}, dir, filepath.Join(dir, "cache"), opts)
			if err == nil {
				t.Fatal("unadmitted bearer realm succeeded")
			}
			if requests.Load() != 0 {
				if credentials.Load() {
					t.Fatal("registry credentials were sent to a bearer realm outside the admitted authentication scope")
				}
				t.Fatal("an unadmitted bearer realm received a request")
			}
			if strings.Contains(err.Error(), "realm-query-secret") || strings.Contains(err.Error(), "origin-password") {
				t.Fatal("source error disclosed a token URL or password")
			}
		})
	}
}

func TestExplicitHTTPSAuthenticationHostCanIssueRegistryToken(t *testing.T) {
	ctx := context.Background()
	source, root := imageFixture(t)
	var issued atomic.Int64
	realm := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "reader" || password != "private-password" {
			t.Error("explicit authentication host did not receive its admitted credentials")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		issued.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"token":"scoped-registry-token"}`))
	}))
	defer realm.Close()
	registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer scoped-registry-token" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm.URL+`/token",service="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		d := strings.TrimPrefix(r.URL.Path, "/v2/private/manifests/")
		if !strings.HasPrefix(r.URL.Path, "/v2/private/manifests/") {
			d = strings.TrimPrefix(r.URL.Path, "/v2/private/blobs/")
		}
		if d == "latest" {
			d = root.Digest.String()
		}
		p, err := BlobPath(source, d)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(p)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", root.MediaType)
		w.Header().Set("Docker-Content-Digest", d)
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		if r.Method != http.MethodHead {
			w.Write(data)
		}
	}))
	defer registry.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "source-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(registry.URL, "https://")
	asset, err := lockImageWithOptions(ctx, spec.Asset{ID: "private", Type: "image", Source: host + "/private:latest", Platform: "linux/amd64"}, dir, filepath.Join(dir, "cache"), RegistryOptions{CAFile: ca, Username: "reader", Password: "private-password", AllowedAuthHosts: []string{strings.TrimPrefix(realm.URL, "https://")}})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Load() == 0 || asset.Digest != root.Digest.String() || len(asset.Files) != 3 {
		t.Fatal("explicit authentication did not produce the complete immutable image graph")
	}
}

func TestPrivateSourceRegistryAndCDNAdmission(t *testing.T) {
	ctx := context.Background()
	source, root := imageFixture(t)
	store, err := oci.New(source)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := imageGraph(ctx, store, root)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "source-secret-not-in-portable-metadata"
	var leaked atomic.Bool
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
			leaked.Store(true)
		}
		d := strings.TrimPrefix(r.URL.Path, "/objects/")
		p, err := BlobPath(source, d)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(p)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	defer cdn.Close()
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "source-user" || password != secret {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		d := strings.TrimPrefix(r.URL.Path, "/v2/private/manifests/")
		isManifest := strings.HasPrefix(r.URL.Path, "/v2/private/manifests/")
		if !isManifest {
			d = strings.TrimPrefix(r.URL.Path, "/v2/private/blobs/")
		}
		if d == "demo" {
			d = root.Digest.String()
		}
		var size int64
		found := false
		for _, f := range graph {
			if f.Digest == d {
				found = true
				size = f.Size
				break
			}
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		if !isManifest {
			http.Redirect(w, r, cdn.URL+"/objects/"+d+"?token=must-not-leak", http.StatusTemporaryRedirect)
			return
		}
		p, _ := BlobPath(source, d)
		b, err := os.ReadFile(p)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", root.MediaType)
		w.Header().Set("Docker-Content-Digest", d)
		w.Header().Set("Content-Length", fmt.Sprint(size))
		if r.Method != http.MethodHead {
			w.Write(b)
		}
	}))
	defer registry.Close()
	host := strings.TrimPrefix(registry.URL, "http://")
	cdnHost := strings.TrimPrefix(cdn.URL, "http://")
	f := newFixture(t)
	var release spec.Release
	if err := spec.Read(filepath.Join(f.dir, "release.json"), &release); err != nil {
		t.Fatal(err)
	}
	release.Spec.Assets = append(release.Spec.Assets, spec.Asset{ID: "private-image", Type: "image", Source: host + "/private:demo", Platform: "linux/amd64", AllowedRedirectHosts: []string{cdnHost}})
	p := filepath.Join(f.dir, "private-source.json")
	if err := spec.Write(p, release); err != nil {
		t.Fatal(err)
	}
	opts := LockOptions{Registries: map[string]RegistryOptions{host: {PlainHTTP: true, Username: "source-user", Password: secret}}}
	lock, err := LockWithOptions(ctx, p, filepath.Join(f.dir, "authenticated-cache"), opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) || strings.Contains(string(b), "must-not-leak") {
		t.Fatal("source credentials or redirect tokens entered portable metadata")
	}
	if leaked.Load() {
		t.Fatal("registry credentials reached CDN")
	}
	asset := release.Spec.Assets[len(release.Spec.Assets)-1]
	asset.AllowedRedirectHosts = nil
	if _, err := lockImageWithOptions(ctx, asset, f.dir, filepath.Join(f.dir, "blocked-cdn-cache"), opts.Registries[host]); err == nil {
		t.Fatal("unadmitted CDN was followed")
	} else if strings.Contains(err.Error(), "must-not-leak") {
		t.Fatal("redirect URL token entered error text")
	}
	wrong := LockOptions{Registries: map[string]RegistryOptions{host: {PlainHTTP: true}, "other.example": {Username: "source-user", Password: secret}}}
	if _, err := LockWithOptions(ctx, p, filepath.Join(f.dir, "wrong-host-cache"), wrong); err == nil {
		t.Fatal("credentials were used for an unmatched source scope")
	}
}

func TestHTTPSAssetRedirectAndPrivateOptions(t *testing.T) {
	ctx := context.Background()
	payload := []byte("pinned model bytes")
	const secret = "private-download-credential"
	var leaked atomic.Bool
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		w.Write(payload)
	}))
	defer cdn.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "source-user" || password != secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, cdn.URL+"/model?token=hidden-token", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	asset := spec.Asset{ID: "model", Type: "file", Source: origin.URL + "/artifact.bin", Digest: spec.Hash(payload), AllowedRedirectHosts: []string{strings.TrimPrefix(cdn.URL, "https://")}}
	opts := RegistryOptions{CAFile: ca, Username: "source-user", Password: secret, AllowedRedirectHosts: asset.AllowedRedirectHosts}
	if _, err := lockFilesWithOptions(ctx, asset, dir, filepath.Join(dir, "cache"), opts); err != nil {
		t.Fatal(err)
	}
	if leaked.Load() {
		t.Fatal("HTTP source credentials leaked across an admitted redirect")
	}
	opts.AllowedRedirectHosts = nil
	if _, err := lockFilesWithOptions(ctx, asset, dir, filepath.Join(dir, "blocked"), opts); err == nil {
		t.Fatal("unadmitted HTTPS redirect accepted")
	} else if strings.Contains(err.Error(), "hidden-token") {
		t.Fatal("query token leaked through redirect error")
	}
	options := LockOptions{Registries: map[string]RegistryOptions{strings.TrimPrefix(origin.URL, "https://"): {CAFile: ca, Username: "source-user", Password: secret}}}
	p := filepath.Join(dir, "source-auth.json")
	b, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLockOptions(p); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, 0644)
	if _, err := ReadLockOptions(p); err == nil {
		t.Fatal("insecure source-auth file accepted")
	}
}
