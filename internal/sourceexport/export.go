// Package sourceexport prepares an independently admitted source distribution.
// Its manifest establishes file integrity, not release or execution authority.
package sourceexport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
)

const maxFiles = 100000
const maxFileBytes int64 = 1 << 30
const maxTotalBytes int64 = 8 << 30

type Options struct {
	GoBinary         string
	IncludeToolchain string
	HelmPath         string
	HelmNotices      string
}

type Tool struct {
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest"`
	OS      string `json:"os,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Bundled bool   `json:"bundled"`
	Notices string `json:"notices,omitempty"`
}

type Manifest struct {
	spec.Header
	Module       string            `json:"module"`
	BuildPackage string            `json:"buildPackage"`
	Go           Tool              `json:"go"`
	Helm         *Tool             `json:"helm,omitempty"`
	GoModDigest  string            `json:"goModDigest"`
	GoSumDigest  string            `json:"goSumDigest,omitempty"`
	Files        []spec.FileRecord `json:"files"`
	Coverage     []string          `json:"coverage"`
}

type goEnvironment struct {
	GOVERSION string
	GOROOT    string
	GOOS      string
	GOARCH    string
}

// Export copies only admitted public project paths, vendors dependencies in
// private staging, and writes the manifest last. An existing output is rejected.
// GoBinary is an explicit matching Go executable. IncludeToolchain optionally
// names that executable's complete GOROOT distribution, not an arbitrary tree.
func Export(ctx context.Context, projectRoot, outDir string, options Options) (manifest Manifest, resultErr error) {
	if options.GoBinary == "" {
		return manifest, spec.Err(2, "source export requires an explicit approved Go executable")
	}
	if (options.HelmPath == "") != (options.HelmNotices == "") {
		return manifest, spec.Err(2, "Helm executable and operator-admitted Helm notice directory must be supplied together")
	}
	goBinary, err := filepath.Abs(options.GoBinary)
	if err != nil {
		return manifest, err
	}
	goDigest, _, err := hashRegular(ctx, goBinary)
	if err != nil {
		return manifest, fmt.Errorf("approved Go executable: %w", err)
	}
	root, err := filepath.Abs(projectRoot)
	if err != nil {
		return manifest, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return manifest, err
	}
	out, err := filepath.Abs(outDir)
	if err != nil {
		return manifest, err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		return manifest, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(out))
	if err != nil {
		return manifest, err
	}
	out = filepath.Join(parent, filepath.Base(out))
	if out == root {
		return manifest, spec.Err(2, "source export cannot replace its source workspace")
	}
	if relative, err := filepath.Rel(root, out); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		top := strings.Split(relative, string(filepath.Separator))[0]
		if publicSource(top, true) {
			return manifest, spec.Err(2, "source export cannot be nested inside an admitted source tree")
		}
	}
	if err := os.Mkdir(out, 0700); err != nil {
		return manifest, err
	}
	defer func() {
		if resultErr != nil {
			_ = os.RemoveAll(out)
		}
	}()
	source := filepath.Join(out, "source")
	if err := copySelected(ctx, root, source, publicSource); err != nil {
		return manifest, err
	}
	for _, required := range []string{"go.mod", "LICENSE", "cmd/cinderlock/main.go"} {
		if _, _, err := hashRegular(ctx, filepath.Join(source, required)); err != nil {
			return manifest, spec.Err(2, "source export is missing required public source %s", required)
		}
	}
	work, err := os.MkdirTemp("", "cinderlock-source-preparation-")
	if err != nil {
		return manifest, err
	}
	defer os.RemoveAll(work)
	producerEnv := commandEnvironment(work, false)
	goEnv, err := inspectGo(ctx, goBinary, work, producerEnv)
	if err != nil {
		return manifest, err
	}
	metadata, err := command(ctx, goBinary, source, producerEnv, "mod", "edit", "-json")
	if err != nil {
		return manifest, err
	}
	var module struct {
		Module  struct{ Path string }
		Replace []struct {
			New struct{ Path, Version string }
		}
	}
	if err := json.Unmarshal(metadata, &module); err != nil || module.Module.Path == "" {
		return manifest, spec.Err(2, "source module identity cannot be established")
	}
	for _, replacement := range module.Replace {
		if replacement.New.Version == "" {
			return manifest, spec.Err(2, "local module replacements cannot enter a portable source export")
		}
	}
	modDigest, _, err := hashRegular(ctx, filepath.Join(source, "go.mod"))
	if err != nil {
		return manifest, err
	}
	sumDigest, _, err := hashRegular(ctx, filepath.Join(source, "go.sum"))
	if errors.Is(err, os.ErrNotExist) {
		sumDigest, err = "", nil
	}
	if err != nil {
		return manifest, err
	}
	if _, err := command(ctx, goBinary, source, producerEnv, "mod", "vendor"); err != nil {
		return manifest, err
	}
	if actual, _, err := hashRegular(ctx, filepath.Join(source, "go.mod")); err != nil || actual != modDigest {
		return manifest, spec.Err(12, "vendoring changed the admitted go.mod")
	}
	actualSum, _, sumErr := hashRegular(ctx, filepath.Join(source, "go.sum"))
	if errors.Is(sumErr, os.ErrNotExist) && sumDigest == "" {
		actualSum, sumErr = "", nil
	}
	if sumErr != nil || actualSum != sumDigest {
		return manifest, spec.Err(12, "vendoring changed the admitted go.sum")
	}
	manifest = Manifest{Header: spec.NewHeader("SourceExport"), Module: module.Module.Path, BuildPackage: "./cmd/cinderlock", Go: Tool{Version: goEnv.GOVERSION, Digest: goDigest, OS: goEnv.GOOS, Arch: goEnv.GOARCH}, GoModDigest: modDigest, GoSumDigest: sumDigest, Coverage: []string{"Public source allowlist and Go-vendored dependencies, including Go vendor license copies", "File inventory only; independent source/toolchain admission is required", "No vulnerability, secret-content, model-quality, or hardware qualification is implied"}}
	manifest.Metadata.Name = "cinderlock-source"
	if options.IncludeToolchain != "" {
		distribution, err := filepath.Abs(options.IncludeToolchain)
		if err != nil {
			return manifest, err
		}
		info, err := os.Lstat(distribution)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return manifest, spec.Err(2, "included Go toolchain must be a real distribution directory")
		}
		resolved, err := filepath.EvalSymlinks(distribution)
		if err != nil || resolved != filepath.Clean(goEnv.GOROOT) {
			return manifest, spec.Err(2, "included toolchain differs from the selected Go executable's GOROOT")
		}
		if digest, _, err := hashRegular(ctx, filepath.Join(distribution, "bin", "go")); err != nil || digest != goDigest {
			return manifest, spec.Err(12, "included toolchain Go executable identity differs")
		}
		if err := copySelected(ctx, distribution, filepath.Join(out, "toolchain", "go"), distributionSource); err != nil {
			return manifest, err
		}
		manifest.Go.Bundled = true
	}
	if options.HelmPath != "" {
		notices, err := filepath.Abs(options.HelmNotices)
		if err != nil {
			return manifest, err
		}
		if err := validateNotices(ctx, notices); err != nil {
			return manifest, err
		}
		notices, err = filepath.EvalSymlinks(notices)
		if err != nil {
			return manifest, err
		}
		if relative, err := filepath.Rel(notices, out); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return manifest, spec.Err(2, "source export cannot be nested inside its admitted legal notices")
		}
		digest, _, err := hashRegular(ctx, options.HelmPath)
		if err != nil {
			return manifest, err
		}
		if err := copyRegular(ctx, options.HelmPath, filepath.Join(out, "tools", "helm")); err != nil {
			return manifest, err
		}
		if err := copySelected(ctx, notices, filepath.Join(out, "tools", "helm-notices"), func(string, bool) bool { return true }); err != nil {
			return manifest, err
		}
		manifest.Helm = &Tool{Digest: digest, Bundled: true, Notices: "tools/helm-notices"}
		manifest.Coverage = append(manifest.Coverage, "Helm legal notices are operator-supplied; their correspondence and completeness are not independently attested")
	}
	if err := spec.WriteBytes(filepath.Join(out, "BUILD-OFFLINE.md"), []byte(buildInstructions)); err != nil {
		return manifest, err
	}
	manifest.Files, err = inventory(ctx, out)
	if err != nil {
		return manifest, err
	}
	if err := spec.Write(filepath.Join(out, "manifest.json"), manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func inspectGo(ctx context.Context, binary, work string, env []string) (goEnvironment, error) {
	var result goEnvironment
	data, err := command(ctx, binary, work, env, "env", "-json", "GOVERSION", "GOROOT", "GOOS", "GOARCH")
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(data, &result); err != nil || !regexp.MustCompile(`^go1\.[0-9]+(?:\.[0-9]+)?$`).MatchString(result.GOVERSION) || result.GOROOT == "" || result.GOOS == "" || result.GOARCH == "" {
		return result, spec.Err(2, "approved Go executable did not return a stable toolchain identity")
	}
	return result, nil
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 1<<20 {
		return 0, errors.New("source preparation output exceeds limit")
	}
	return b.Buffer.Write(data)
}

func command(ctx context.Context, binary, dir string, env []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir, cmd.Env = dir, env
	var stdout, stderr boundedOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, spec.Err(17, "source preparation or offline build was interrupted")
		}
		// Module proxy errors may contain private URLs. Do not return raw output.
		return nil, spec.Err(10, "approved Go command failed; check the selected toolchain and admitted module access")
	}
	return stdout.Bytes(), nil
}

func commandEnvironment(work string, offline bool) []string {
	values := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	// A relocated distribution must discover its own GOROOT. Native producer
	// identity must not be confused with ambient cross-compilation preferences.
	for _, key := range []string{"GOROOT", "GOOS", "GOARCH", "GOAMD64", "GOARM", "GOARM64", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "GOEXPERIMENT"} {
		delete(values, key)
	}
	for key, value := range map[string]string{"GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOCACHE": filepath.Join(work, "build-cache")} {
		values[key] = value
	}
	if offline {
		for key, value := range map[string]string{"GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none", "GONOSUMDB": "none", "GOPRIVATE": "", "GOPATH": filepath.Join(work, "gopath"), "GOMODCACHE": filepath.Join(work, "module-cache"), "CGO_ENABLED": "0", "HOME": work} {
			values[key] = value
		}
	}
	result := make([]string, 0, len(values))
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	return result
}

const buildInstructions = `# Build the admitted source offline

Independently admit manifest.json and the source/toolchain identities before
transfer. Run cinderlock source verify against the received tree. The manifest
is a file inventory, not a signature, scanner result, or source admission.

Use the exact Go executable digest/version named in the manifest. If included,
the distribution is under toolchain/go. Otherwise supply the already admitted
matching Go distribution locally. The optional tools/helm binary is inventoried
but has not been executed or qualified by this export.

From source/, build with the approved Go executable:

    GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off GOENV=off CGO_ENABLED=0 \
      /approved/go/bin/go build -mod=vendor -trimpath -o /approved/build-output/cinderlock ./cmd/cinderlock

Use an empty module cache to check that only vendored dependencies are used.
Disabling online checksum lookup inside the gap is not an integrity substitute;
the source, vendor tree, licenses, and Go distribution must already be admitted.
The export command does not run this build automatically. The separate source
build command publishes a new executable outside this inventoried directory,
without overwriting an existing file. It does not run or qualify that binary.
`
