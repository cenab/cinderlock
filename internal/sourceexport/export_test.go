package sourceexport

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func approvedGo(t *testing.T) string {
	t.Helper()
	name := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(name); err != nil {
		t.Fatal("matching Go distribution is required for source-export tests:", err)
	}
	return name
}

func writeFixture(t *testing.T, root, name, data string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func smallProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "go.mod", "module example.com/source-fixture\n\ngo 1.24.0\n")
	writeFixture(t, root, "LICENSE", "fixture-license\n")
	writeFixture(t, root, "cmd/cinderlock/main.go", "package main\nfunc main() { panic(\"compile only; must not execute\") }\n")
	return root
}

func TestPublicGoSourceNamesDoNotDropConfigurationOrSecretReferenceCode(t *testing.T) {
	root := smallProject(t)
	writeFixture(t, root, "cmd/cinderlock/main.go", "package main\nimport \"example.com/source-fixture/internal/transport\"\nfunc main() { println(transport.ConfigLabel(), transport.SecretLabel()) }\n")
	files := map[string]string{
		"internal/transport/kubeconfig_snapshot.go": "package transport\nfunc ConfigLabel() string { return \"public configuration API\" }\n",
		"internal/transport/secret_reference.go":    "package transport\nfunc SecretLabel() string { return \"public reference API\" }\n",
	}
	for name, data := range files {
		writeFixture(t, root, name, data)
	}
	out := filepath.Join(t.TempDir(), "export")
	if _, err := Export(context.Background(), root, out, Options{GoBinary: approvedGo(t)}); err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(out, "source", name))
		if err != nil || string(got) != want {
			t.Fatalf("required public source was excluded: %s: %v", name, err)
		}
	}
	if err := BuildOffline(context.Background(), out, approvedGo(t), filepath.Join(t.TempDir(), "cinderlock")); err != nil {
		t.Fatal(err)
	}
}

func TestSourceExportExcludesPrivatePathsAndBuildsOffline(t *testing.T) {
	root := smallProject(t)
	for _, name := range []string{".local/receipt.json", ".git/config", ".env", "docs/private/token.md", "examples/app/kubeconfig.yaml", "internal/credentials/token.go", "unselected/customer.json"} {
		writeFixture(t, root, name, "private-value-must-not-enter-distribution")
	}
	writeFixture(t, root, "README.md", "Public build fixture\n")
	for _, name := range []string{"CONTRIBUTING.md", "NOTICE", "tests/integration/kind.py", "tests/integration/README.md", "deploy/catalog/chart/templates/service.yaml", "deploy/catalog/chart/templates/_helpers.tpl", "tools/helm/go.mod", "tools/helm/go.sum", "tools/helm/prepare.sh", "tools/helm/prepare.py"} {
		writeFixture(t, root, name, "public-source-fixture\n")
	}
	out := filepath.Join(t.TempDir(), "export")
	manifest, err := Export(context.Background(), root, out, Options{GoBinary: approvedGo(t)})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Go.Bundled || manifest.Module != "example.com/source-fixture" || manifest.GoModDigest == "" {
		t.Fatalf("incorrect source/toolchain provenance: %#v", manifest)
	}
	for _, file := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(out, file.Path))
		if err != nil || bytes.Contains(data, []byte("private-value-must-not-enter-distribution")) {
			t.Fatalf("private content entered export: %s %v", file.Path, err)
		}
	}
	for _, name := range []string{"CONTRIBUTING.md", "NOTICE", "tests/integration/kind.py", "tests/integration/README.md", "deploy/catalog/chart/templates/service.yaml", "deploy/catalog/chart/templates/_helpers.tpl", "tools/helm/go.mod", "tools/helm/go.sum", "tools/helm/prepare.sh", "tools/helm/prepare.py"} {
		if data, err := os.ReadFile(filepath.Join(out, "source", name)); err != nil || string(data) != "public-source-fixture\n" {
			t.Fatal("public integration/install source was excluded", name, err)
		}
	}
	if _, err := Verify(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "cinderlock")
	if err := BuildOffline(context.Background(), out, approvedGo(t), binary); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0700 || info.Size() == 0 {
		t.Fatal("offline build did not publish a private executable", info, err)
	}
	before, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := BuildOffline(context.Background(), out, approvedGo(t), binary); !os.IsExist(err) {
		t.Fatal("existing executable was not protected", err)
	}
	if after, err := os.ReadFile(binary); err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected publication changed existing executable", err)
	}
	if _, err := Export(context.Background(), root, out, Options{GoBinary: approvedGo(t)}); err == nil {
		t.Fatal("existing reviewed distribution was overwritten")
	}
}

func TestVendoredModuleAndLicenseBuildWithoutProxy(t *testing.T) {
	const module = "example.com/dependency"
	const version = "v1.0.0"
	mod := "module " + module + "\n\ngo 1.24.0\n"
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for name, data := range map[string]string{"go.mod": mod, "LICENSE": "upstream-fixture-license\n", "dependency.go": "package dependency\nfunc Identity() string { return \"vendored\" }\n"} {
		f, err := zw.Create(module + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/" + module + "/@v/" + version + ".mod":
			fmt.Fprint(w, mod)
		case "/" + module + "/@v/" + version + ".info":
			fmt.Fprintf(w, `{"Version":%q,"Time":"2026-01-01T00:00:00Z"}`, version)
		case "/" + module + "/@v/" + version + ".zip":
			w.Write(archive.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer proxy.Close()
	t.Setenv("GOPROXY", proxy.URL)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "none")
	moduleCache := filepath.Join(t.TempDir(), "module-cache")
	t.Setenv("GOMODCACHE", moduleCache)
	t.Cleanup(func() {
		// Go deliberately makes module-cache directories read-only. Restore only
		// this test's private fixture directories before TempDir removes them.
		_ = filepath.WalkDir(moduleCache, func(name string, entry fs.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				return os.Chmod(name, 0700)
			}
			return err
		})
	})
	root := smallProject(t)
	writeFixture(t, root, "go.mod", "module example.com/source-fixture\n\ngo 1.24.0\n\nrequire "+module+" "+version+"\n")
	writeFixture(t, root, "cmd/cinderlock/main.go", "package main\nimport \""+module+"\"\nfunc main() { println(dependency.Identity()) }\n")
	if _, err := command(context.Background(), approvedGo(t), root, commandEnvironment(t.TempDir(), false), "mod", "tidy"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "export")
	if _, err := Export(context.Background(), root, out, Options{GoBinary: approvedGo(t)}); err != nil {
		t.Fatal(err)
	}
	license, err := os.ReadFile(filepath.Join(out, "source", "vendor", module, "LICENSE"))
	if err != nil || string(license) != "upstream-fixture-license\n" {
		t.Fatal("vendor license was not retained", err)
	}
	before := requests.Load()
	if err := BuildOffline(context.Background(), out, approvedGo(t), filepath.Join(t.TempDir(), "cinderlock")); err != nil {
		t.Fatal(err)
	}
	if before == 0 || requests.Load() != before {
		t.Fatal("offline build used the source proxy or fixture never acquired a dependency")
	}
}

func TestSourceExportRejectsLinksLocalReplacementsAndNestedOutputs(t *testing.T) {
	for _, scenario := range []string{"symlink", "local-replacement", "nested-output", "cancelled", "toolchain-mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			root := smallProject(t)
			out := filepath.Join(t.TempDir(), "export")
			opts := Options{GoBinary: approvedGo(t)}
			ctx := context.Background()
			switch scenario {
			case "symlink":
				outside := filepath.Join(t.TempDir(), "outside.go")
				if err := os.WriteFile(outside, []byte("private source"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(root, "cmd", "cinderlock", "linked.go")); err != nil {
					t.Fatal(err)
				}
			case "local-replacement":
				writeFixture(t, root, "go.mod", "module example.com/source-fixture\n\ngo 1.24.0\n\nreplace example.com/private => /private/local-source\n")
			case "nested-output":
				out = filepath.Join(root, "internal", "recursive-output")
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "toolchain-mismatch":
				opts.IncludeToolchain = t.TempDir()
			}
			if _, err := Export(ctx, root, out, opts); err == nil {
				t.Fatal("unsafe source export accepted")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("failed export left a published output directory", err)
			}
		})
	}
}

func TestSourceExportVerificationRejectsChangedAndExtraFiles(t *testing.T) {
	root := smallProject(t)
	out := filepath.Join(t.TempDir(), "export")
	manifest, err := Export(context.Background(), root, out, Options{GoBinary: approvedGo(t)})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(out, "source", "LICENSE")
	if err := os.WriteFile(p, []byte("changed"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), out); spec.ExitCode(err) != 12 {
		t.Fatal("changed source was not rejected", err)
	}
	if err := os.WriteFile(p, []byte("fixture-license\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "private-extra"), []byte("not inventoried"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), out); err == nil {
		t.Fatal("unlisted files accepted")
	}
	if err := os.Remove(filepath.Join(out, "private-extra")); err != nil {
		t.Fatal(err)
	}
	manifest.Files[0].Path = "../escape"
	data, err := spec.Canonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), out); err == nil {
		t.Fatal("traversing manifest path accepted")
	}
}

func TestOfflineBuildNeverPublishesRejectedOrUncompilableSources(t *testing.T) {
	root := smallProject(t)
	out := filepath.Join(t.TempDir(), "export")
	manifest, err := Export(context.Background(), root, out, Options{GoBinary: approvedGo(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := BuildOffline(context.Background(), out, approvedGo(t), filepath.Join(out, "unlisted-binary")); err == nil {
		t.Fatal("build output may modify its inventoried input")
	}
	writeFixture(t, out, "source/cmd/cinderlock/main.go", "package main\nfunc main() { compiler-private-token invalid syntax }\n")
	manifest.Files, err = inventory(context.Background(), out)
	if err != nil {
		t.Fatal(err)
	}
	data, err := spec.Canonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "must-not-exist")
	if err := BuildOffline(context.Background(), out, approvedGo(t), binary); err == nil || strings.Contains(err.Error(), "compiler-private-token") {
		t.Fatal("failed build succeeded or exposed raw compiler/source text", err)
	}
	if _, err := os.Stat(binary); !os.IsNotExist(err) {
		t.Fatal("failed compile published an executable", err)
	}
}

func TestHelmExportRequiresAdmittedNoticesAndBindsTheirContents(t *testing.T) {
	root := smallProject(t)
	helm := filepath.Join(t.TempDir(), "helm")
	if err := os.WriteFile(helm, []byte("opaque admitted Helm binary fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"missing-notices", "missing-license", "symlink", "self-containing"} {
		t.Run(scenario, func(t *testing.T) {
			notices := t.TempDir()
			out := filepath.Join(t.TempDir(), "export")
			opts := Options{GoBinary: approvedGo(t), HelmPath: helm, HelmNotices: notices}
			switch scenario {
			case "missing-notices":
				opts.HelmNotices = ""
			case "missing-license":
				writeFixture(t, notices, "README.md", "No root legal notice\n")
			case "symlink":
				writeFixture(t, notices, "LICENSE", "Operator-admitted license fixture\n")
				if err := os.Symlink(helm, filepath.Join(notices, "linked")); err != nil {
					t.Fatal(err)
				}
			case "self-containing":
				writeFixture(t, notices, "LICENSE", "Operator-admitted license fixture\n")
				out = filepath.Join(notices, "recursive-export")
			}
			if _, err := Export(context.Background(), root, out, opts); err == nil {
				t.Fatal("missing or unsafe legal input was accepted")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("rejected legal inputs left an output", err)
			}
		})
	}
	notices := t.TempDir()
	writeFixture(t, notices, "LICENSE", "Operator-admitted license fixture\n")
	writeFixture(t, notices, "dependency/NOTICE.txt", "Retained dependency notice\n")
	out := filepath.Join(t.TempDir(), "export")
	manifest, err := Export(context.Background(), root, out, Options{GoBinary: approvedGo(t), HelmPath: helm, HelmNotices: notices})
	if err != nil || manifest.Helm == nil || manifest.Helm.Notices != "tools/helm-notices" {
		t.Fatal("Helm legal inputs were not bound", err)
	}
	if _, err := Verify(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(out, "tools", "helm-notices", "dependency", "NOTICE.txt")); err != nil || string(data) != "Retained dependency notice\n" {
		t.Fatal("recursive notice missing", err)
	}
	if err := os.WriteFile(filepath.Join(out, "tools", "helm-notices", "LICENSE"), []byte("changed"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), out); err == nil {
		t.Fatal("changed legal notice was accepted")
	}
}

func TestProjectSourceExportBuildsOffline(t *testing.T) {
	if os.Getenv("CINDERLOCK_TEST_SOURCE_EXPORT") != "1" {
		t.Skip("CINDERLOCK_TEST_SOURCE_EXPORT=1 enables the complete project/vendor/toolchain build")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "complete-export")
	options := Options{GoBinary: approvedGo(t), IncludeToolchain: runtime.GOROOT(), HelmPath: os.Getenv("CINDERLOCK_TEST_HELM"), HelmNotices: os.Getenv("CINDERLOCK_TEST_HELM_NOTICES")}
	manifest, err := Export(context.Background(), root, out, options)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.Go.Bundled || !strings.HasPrefix(manifest.Module, "github.com/") {
		t.Fatal("complete project/toolchain identity missing")
	}
	binary := filepath.Join(t.TempDir(), "cinderlock")
	if err := BuildOffline(context.Background(), out, "", binary); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(binary); err != nil || info.Size() == 0 || info.Mode().Perm() != 0700 {
		t.Fatal("complete source build did not publish a private executable", err)
	}
	t.Logf("complete project/vendor/toolchain inventory: %d files; offline build passed", len(manifest.Files))
}
