package sourceexport

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
)

// Verify checks all regular files and rejects missing, modified, or extra
// content. The caller must independently admit the expected manifest identity.
func Verify(ctx context.Context, directory string) (manifest Manifest, err error) {
	root, err := openTree(directory)
	if err != nil {
		return manifest, err
	}
	defer root.Close()
	return verifyAt(ctx, root)
}

func verifyAt(ctx context.Context, root *os.Root) (manifest Manifest, err error) {
	file, info, err := openRegularAt(root, "manifest.json", nil)
	if err != nil {
		return manifest, err
	}
	defer file.Close()
	if info.Size() > spec.MaxDocumentBytes {
		return manifest, spec.Err(2, "source manifest exceeds document limit")
	}
	data, err := io.ReadAll(contextReader{ctx, io.LimitReader(file, spec.MaxDocumentBytes+1)})
	if err != nil {
		return manifest, err
	}
	if !unchanged(file, info, int64(len(data))) {
		return manifest, spec.Err(12, "source manifest changed while reading")
	}
	if err := spec.Decode(data, &manifest); err != nil {
		return manifest, err
	}
	if err := spec.ValidateHeader(manifest.Header, "SourceExport"); err != nil {
		return manifest, err
	}
	if manifest.Module == "" || manifest.BuildPackage != "./cmd/cinderlock" || !spec.ValidDigest(manifest.Go.Digest) || !spec.ValidDigest(manifest.GoModDigest) || len(manifest.Files) == 0 || len(manifest.Files) > maxFiles {
		return manifest, spec.Err(12, "source export identity or build contract is invalid")
	}
	actual, err := inventoryAt(ctx, root)
	if err != nil {
		return manifest, err
	}
	actualDigest, err := spec.Digest(struct{ Files []spec.FileRecord }{actual})
	if err != nil {
		return manifest, err
	}
	expected, err := spec.Digest(struct{ Files []spec.FileRecord }{manifest.Files})
	if err != nil || actualDigest != expected {
		return manifest, spec.Err(12, "source export contents differ from the manifest")
	}
	if digest, _, err := hashRegularAt(ctx, root, "source/go.mod", nil); err != nil || digest != manifest.GoModDigest {
		return manifest, spec.Err(12, "source export module identity differs")
	}
	if manifest.GoSumDigest != "" {
		if digest, _, err := hashRegularAt(ctx, root, "source/go.sum", nil); err != nil || digest != manifest.GoSumDigest {
			return manifest, spec.Err(12, "source export module checksum identity differs")
		}
	}
	if manifest.Go.Bundled {
		if digest, _, err := hashRegularAt(ctx, root, "toolchain/go/bin/go", nil); err != nil || digest != manifest.Go.Digest {
			return manifest, spec.Err(12, "source export bundled Go identity differs")
		}
	}
	if manifest.Helm != nil {
		if !manifest.Helm.Bundled || manifest.Helm.Notices != "tools/helm-notices" {
			return manifest, spec.Err(12, "Helm identity must refer to the bundled executable")
		}
		if digest, _, err := hashRegularAt(ctx, root, "tools/helm", nil); err != nil || digest != manifest.Helm.Digest {
			return manifest, spec.Err(12, "source export Helm identity differs")
		}
		legal, err := root.OpenRoot("tools/helm-notices")
		if err != nil {
			return manifest, err
		}
		err = validateNoticesAt(ctx, legal)
		legal.Close()
		if err != nil {
			return manifest, err
		}
	}
	return manifest, nil
}

// BuildOffline verifies the admitted tree and compiles its fixed CLI package
// with an empty module cache, vendoring, and all Go network lookup disabled.
// Compilation uses a private snapshot verified against the initial manifest,
// never the mutable input tree. It publishes exclusively after reverifying that
// snapshot and never runs the output binary.
func BuildOffline(ctx context.Context, directory, goBinary, outPath string) error {
	if outPath == "" {
		return spec.Err(2, "offline build requires a new output executable path")
	}
	out, err := filepath.Abs(outPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(out))
	if err != nil {
		return err
	}
	out = filepath.Join(parent, filepath.Base(out))
	inputRoot, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(inputRoot)
	if err != nil {
		return err
	}
	if relative, err := filepath.Rel(root, out); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return spec.Err(2, "build output must stay outside the inventoried source export")
	}
	if _, err := os.Lstat(out); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	admitted, err := openTree(directory)
	if err != nil {
		return err
	}
	defer admitted.Close()
	manifest, err := verifyAt(ctx, admitted)
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "cinderlock-offline-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	snapshot := filepath.Join(work, "admitted")
	if err := copyTree(ctx, admitted, snapshot, func(string, bool) bool { return true }, true); err != nil {
		return err
	}
	captured, err := Verify(ctx, snapshot)
	if err != nil {
		return err
	}
	initialDigest, _ := spec.Digest(manifest)
	capturedDigest, _ := spec.Digest(captured)
	if initialDigest != capturedDigest {
		return spec.Err(12, "source export changed while taking the build snapshot")
	}
	if goBinary == "" && manifest.Go.Bundled {
		goBinary = filepath.Join(snapshot, "toolchain", "go", "bin", "go")
	}
	if goBinary == "" {
		return spec.Err(2, "offline build requires the admitted matching Go executable")
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		return err
	}
	// Preserve the caller's input-relative identity before resolving a mutable
	// parent. A substituted ancestor must not turn a bundled path into an
	// independently trusted external toolchain.
	for _, originalRoot := range []string{inputRoot, root} {
		if relative, err := filepath.Rel(originalRoot, goBinary); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			goBinary = filepath.Join(snapshot, relative)
			break
		}
	}
	goParent, err := filepath.EvalSymlinks(filepath.Dir(goBinary))
	if err != nil {
		return err
	}
	goBinary = filepath.Join(goParent, filepath.Base(goBinary))
	if relative, err := filepath.Rel(root, goBinary); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		goBinary = filepath.Join(snapshot, relative)
	}
	if digest, _, err := hashRegular(ctx, goBinary); err != nil || digest != manifest.Go.Digest {
		return spec.Err(12, "offline Go executable differs from the admitted identity")
	}
	env := commandEnvironment(work, true)
	observed, err := inspectGo(ctx, goBinary, work, env)
	if err != nil {
		return err
	}
	if observed.GOVERSION != manifest.Go.Version || observed.GOOS != manifest.Go.OS || observed.GOARCH != manifest.Go.Arch {
		return spec.Err(12, "offline Go version or build platform differs from the admitted identity")
	}
	binary := filepath.Join(work, "cinderlock")
	if _, err := command(ctx, goBinary, filepath.Join(snapshot, "source"), env, "build", "-mod=vendor", "-trimpath", "-o", binary, manifest.BuildPackage); err != nil {
		return err
	}
	current, err := Verify(ctx, snapshot)
	if err != nil {
		return err
	}
	currentDigest, _ := spec.Digest(current)
	if initialDigest != currentDigest {
		return spec.Err(12, "source export changed during offline compilation")
	}
	return publishBinary(ctx, binary, out)
}

func publishBinary(ctx context.Context, binary, out string) error {
	input, err := os.Open(binary)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return spec.Err(12, "compiler output is not a supported regular executable")
	}
	file, err := os.CreateTemp(filepath.Dir(out), ".cinderlock-executable-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	if err := file.Chmod(0700); err != nil {
		return err
	}
	n, copyErr := io.Copy(file, contextReader{ctx, io.LimitReader(input, info.Size()+1)})
	if copyErr != nil {
		return copyErr
	}
	if n != info.Size() {
		return spec.Err(12, "compiler output changed during publication")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Link publishes the already-complete inode without replacing an existing
	// file or symlink. The temporary and destination are on one filesystem.
	return os.Link(temporary, out)
}
