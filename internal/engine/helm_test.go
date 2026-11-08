package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func chartFixture(t *testing.T, e *Engine) *bundle.Verified {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct{ name, body string }{{"test/Chart.yaml", "apiVersion: v2\nname: test\nversion: 1.0.0\nappVersion: 2.0.0\n"}, {"test/values.yaml", "setting: default\n"}, {"test/templates/app.yaml", "{{ if .Release.IsUpgrade }}upgrade{{ else }}install{{ end }}"}} {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(entry.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	digest := spec.Hash(buf.Bytes())
	dir := t.TempDir()
	name := filepath.Join(dir, "blobs", "sha256", digest[7:])
	os.MkdirAll(filepath.Dir(name), 0700)
	if err := os.WriteFile(name, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	r := spec.Release{Header: spec.NewHeader("Release"), Spec: spec.ReleaseSpec{Deployment: spec.Deployment{Type: "helm"}}}
	r.Metadata.Version = "2.0.0"
	return &bundle.Verified{Root: dir, Index: spec.BundleIndex{Lock: spec.ReleaseLock{Release: r, Assets: []spec.LockedAsset{{ID: "cinderlock-chart", Type: "file", Digest: digest, Size: int64(buf.Len()), Files: []spec.FileRecord{{Path: "chart.tgz", Digest: digest, Size: int64(buf.Len()), Mode: 0600}}}}}}}
}

func TestUpgradeRenderUsesUpgradeContext(t *testing.T) {
	e, _, _ := fixture(t)
	v := chartFixture(t, e)
	e.HelmRunner = func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "history":
			return []byte(`[{"revision":1,"status":"deployed","app_version":"1.0.0"}]`), nil
		case "get":
			return []byte(`{}`), nil
		case "template":
			if !slices.Contains(args, "--is-upgrade") {
				t.Fatal("upgrade source was validated with install semantics")
			}
			return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fixture\ndata:\n  mode: upgrade\n"), nil
		}
		t.Fatalf("unexpected call: %v", args)
		return nil, nil
	}
	if _, err := e.render(context.Background(), v); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentExecutesOnlyFrozenValidatedObjects(t *testing.T) {
	e, _, _ := fixture(t)
	v := chartFixture(t, e)
	objects := []map[string]any{{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "fixture"}, "data": map[string]any{"literal": "{{ .Release.IsUpgrade }}"}}}
	digest, _ := spec.Digest(objects)
	e.HelmRunner = func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "history":
			return []byte(`[{"revision":1,"status":"deployed","app_version":"1.0.0"}]`), nil
		case "get":
			return []byte(`{}`), nil
		case "template":
			return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fixture\ndata:\n  literal: '{{ .Release.IsUpgrade }}'\n"), nil
		case "upgrade":
			chart := args[2]
			template, err := os.ReadFile(filepath.Join(chart, "templates", "resources.yaml"))
			if err != nil {
				t.Fatal("deploy did not use frozen chart:", err)
			}
			if strings.TrimSpace(string(template)) != "{{ .Files.Get \"files/resources.yaml\" }}" {
				t.Fatal("chart executes source templates")
			}
			data, err := os.ReadFile(filepath.Join(chart, "files", "resources.yaml"))
			if err != nil || !strings.Contains(string(data), "{{ .Release.IsUpgrade }}") {
				t.Fatal("validated literal not preserved", err)
			}
			return nil, nil
		}
		t.Fatalf("unexpected call: %v", args)
		return nil, nil
	}
	if err := e.deploy(context.Background(), spec.Plan{SourceVersion: "1.0.0", DesiredStateDigest: digest}, v); err != nil {
		t.Fatal(err)
	}
}
