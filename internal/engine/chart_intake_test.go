package engine

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestChartIntakeRejectsHiddenTemplateEffects(t *testing.T) {
	tests := []struct {
		name, body string
		allowed    bool
	}{
		{"clock", "kind: ConfigMap\ndata:\n  created: {{ now}}\n", false},
		{"local-timezone", `{{ toDate "2006-01-02" "2026-11-07" | unixEpoch }}`, false},
		{"strict-local-timezone", `{{ mustToDate "2006-01-02" "2026-11-07" | unixEpoch }}`, false},
		{"nested-call", `{{- if true }}{{ (lookup "v1" "Secret" "private" "key").data }}{{ end }}`, false},
		{"computed-template", `{{ tpl (print "{{ now" "}}") . }}`, false},
		{"definition", `{{ define "unused" }}{{ uuidv4 }}{{ end }}kind: ConfigMap`, false},
		{"pipeline", `{{ "abcd" | shuffle }}`, false},
		{"named-chart-helper", `{{ define "chart" }}stable{{ end }}kind: ConfigMap`, true},
		{"safe-values", `kind: ConfigMap
data:
  note: {{ "lookup now uuidv4" | quote }}
  {{- if .Values.enabled }}
  state: {{ .Values.state | default "local" | quote }}
  {{- else }}
  state: disabled
  {{- end }}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := packagedTemplate(t, tt.body)
			err := inspectChart(path, "app")
			if tt.allowed && err != nil {
				t.Fatal(err)
			}
			if !tt.allowed && err == nil {
				t.Fatal("chart with unadmitted template effects passed intake")
			}
		})
	}
	for _, test := range []struct {
		path, body string
		allowed    bool
	}{
		{`app\templates\config.yaml`, `{{ randAlphaNum 8 }}`, false},
		{"app/files/templates/alert.txt", `{{ $labels.instance }}`, true},
		{"app/charts/dependency/templates/unsafe.yaml", `{{ randAlphaNum 8 }}`, false},
	} {
		err := inspectChart(packagedChartMember(t, test.path, test.body), "app")
		if (err == nil) != test.allowed {
			t.Fatalf("unexpected intake result for %q: %v", test.path, err)
		}
	}
}

func TestChartIntakeUsesHelmEffectiveTemplateName(t *testing.T) {
	e, _, _ := fixture(t)
	v := chartFixture(t, e)
	archive := packagedChartMember(t, "app/templates/config.yaml", `{{ define "app/templates/config.yaml" }}helper{{ end }}kind: ConfigMap`, "renamed")
	b, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	digest := spec.Hash(b)
	if err := os.WriteFile(filepath.Join(v.Root, "blobs", "sha256", digest[7:]), b, 0600); err != nil {
		t.Fatal(err)
	}
	a := &v.Index.Lock.Assets[0]
	a.Digest, a.Size, a.Files[0].Digest, a.Files[0].Size = digest, int64(len(b)), digest, int64(len(b))
	_, _, cleanup, err := e.helmFiles(v)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		t.Fatal("intake rejected a deterministic helper because archive and effective chart names differ:", err)
	}
}

func TestChartIntakeDoesNotTreatSizeLimitAsSuccessfulEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.tgz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	padding := make([]byte, 4<<20)
	for i := 0; i < 16; i++ {
		size := len(padding)
		if i == 15 {
			size -= 16 * 512 // End this member at the inspection limit.
		}
		if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("app/files/padding-%d", i), Typeflag: tar.TypeReg, Mode: 0644, Size: int64(size)}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(padding[:size]); err != nil {
			t.Fatal(err)
		}
	}
	body := "{{ now}}"
	if err := tw.WriteHeader(&tar.Header{Name: "app/templates/late.yaml", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	for _, close := range []func() error{tw.Close, gz.Close, f.Close} {
		if err := close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := inspectChart(path, "app"); err == nil {
		t.Fatal("uninspected archive suffix passed the chart intake size limit")
	}
}

func packagedTemplate(t *testing.T, body string) string {
	t.Helper()
	return packagedChartMember(t, "app/templates/config.yaml", body)
}

func packagedChartMember(t *testing.T, member, body string, metadataName ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chart.tgz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if len(metadataName) > 0 {
		metadata := "apiVersion: v2\nname: " + metadataName[0] + "\nversion: 1.0.0\nappVersion: 2.0.0\n"
		if err := tw.WriteHeader(&tar.Header{Name: "app/Chart.yaml", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(metadata))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(metadata)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: member, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	for _, close := range []func() error{tw.Close, gz.Close, f.Close} {
		if err := close(); err != nil {
			t.Fatal(err)
		}
	}
	return path
}
