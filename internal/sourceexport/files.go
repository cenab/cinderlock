package sourceexport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
)

func publicSource(name string, directory bool) bool {
	parts := strings.Split(filepath.ToSlash(name), "/")
	for _, component := range parts {
		if strings.HasPrefix(component, ".") || strings.EqualFold(component, "secrets") || strings.EqualFold(component, "private") || strings.EqualFold(component, "credentials") {
			return false
		}
	}
	if len(parts) == 1 && !directory {
		return slices.Contains([]string{"go.mod", "go.sum", "LICENSE", "NOTICE", "README.md", "SECURITY.md", "CONTRIBUTING.md", "Makefile", "Dockerfile"}, name)
	}
	top := parts[0]
	if !slices.Contains([]string{"cmd", "internal", "docs", "examples", "schemas", "specs", "tests", "deploy", "tools"}, top) {
		return false
	}
	if top == "tools" && len(parts) > 1 && parts[1] != "helm" {
		return false
	}
	if directory {
		return true
	}
	ext := strings.ToLower(filepath.Ext(name))
	// Public Go filenames can describe credential handling without being data.
	if top == "cmd" || top == "internal" {
		return ext == ".go"
	}
	base := strings.ToLower(filepath.Base(name))
	if strings.Contains(base, "kubeconfig") || strings.Contains(base, "credential") || strings.Contains(base, "secret") || strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".env") {
		return false
	}
	if top == "docs" || top == "specs" {
		return ext == ".md"
	}
	if top == "tests" {
		return ext == ".py" || ext == ".md"
	}
	if top == "tools" {
		return slices.Contains([]string{"go.mod", "go.sum", "LICENSE", "NOTICE"}, filepath.Base(name)) || slices.Contains([]string{".go", ".py", ".sh", ".md"}, ext)
	}
	return slices.Contains([]string{".go", ".py", ".md", ".yaml", ".yml", ".json", ".toml", ".tpl"}, ext) || slices.Contains([]string{"Dockerfile", "LICENSE", "NOTICE", "Makefile"}, filepath.Base(name))
}

func distributionSource(name string, _ bool) bool {
	for _, component := range strings.Split(filepath.ToSlash(name), "/") {
		if component == ".git" || component == ".local" {
			return false
		}
	}
	return true
}

func copySelected(ctx context.Context, source, destination string, selectPath func(string, bool) bool) error {
	root, err := openTree(source)
	if err != nil {
		return err
	}
	defer root.Close()
	return copyTree(ctx, root, destination, selectPath, false)
}

func copyTree(ctx context.Context, root *os.Root, destination string, selectPath func(string, bool) bool, preserveMode bool) error {
	var total int64
	count := 0
	if err := os.MkdirAll(destination, 0700); err != nil {
		return err
	}
	return walkRooted(ctx, root, selectPath, func(parent *os.Root, base, relative string, info fs.FileInfo) error {
		target := filepath.Join(destination, filepath.FromSlash(relative))
		if info.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		count++
		if count > maxFiles || info.Size() < 0 || info.Size() > maxTotalBytes-total {
			return spec.Err(2, "source tree exceeds the supported file count or byte limit")
		}
		total += info.Size()
		return copyRegularAt(ctx, parent, base, target, info, preserveMode)
	})
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func hashRegular(ctx context.Context, name string) (string, int64, error) {
	root, err := openTree(filepath.Dir(name))
	if err != nil {
		return "", 0, err
	}
	defer root.Close()
	return hashRegularAt(ctx, root, filepath.Base(name), nil)
}

func hashRegularAt(ctx context.Context, root *os.Root, name string, expected fs.FileInfo) (string, int64, error) {
	f, before, err := openRegularAt(root, name, expected)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, io.LimitReader(f, before.Size()+1)})
	if err != nil {
		return "", 0, err
	}
	if !unchanged(f, before, n) {
		return "", 0, spec.Err(12, "source file changed during hashing")
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}

func copyRegular(ctx context.Context, source, destination string) error {
	root, err := openTree(filepath.Dir(source))
	if err != nil {
		return err
	}
	defer root.Close()
	return copyRegularAt(ctx, root, filepath.Base(source), destination, nil, false)
}

func copyRegularAt(ctx context.Context, root *os.Root, name, destination string, expected fs.FileInfo, preserveMode bool) error {
	input, info, err := openRegularAt(root, name, expected)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	mode := fs.FileMode(0644)
	if info.Mode()&0111 != 0 {
		mode = 0755
	}
	if preserveMode {
		mode = info.Mode().Perm()
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if preserveMode {
		if err := output.Chmod(mode); err != nil {
			output.Close()
			return err
		}
	}
	n, copyErr := io.Copy(output, contextReader{ctx, io.LimitReader(input, info.Size()+1)})
	if !unchanged(input, info, n) {
		copyErr = errors.Join(copyErr, spec.Err(12, "source file changed during copying"))
	}
	syncErr := output.Sync()
	closeErr := output.Close()
	return errors.Join(copyErr, syncErr, closeErr)
}

func inventory(ctx context.Context, directory string) ([]spec.FileRecord, error) {
	root, err := openTree(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return inventoryAt(ctx, root)
}

func inventoryAt(ctx context.Context, root *os.Root) ([]spec.FileRecord, error) {
	files := []spec.FileRecord{}
	var total int64
	err := walkRooted(ctx, root, func(string, bool) bool { return true }, func(parent *os.Root, base, relative string, info fs.FileInfo) error {
		if info.IsDir() {
			return nil
		}
		if relative == "manifest.json" {
			return nil
		}
		if !spec.SafePath(relative) || len(files) >= maxFiles {
			return spec.Err(2, "source inventory path or file count exceeds limit")
		}
		digest, size, err := hashRegularAt(ctx, parent, base, info)
		if err != nil {
			return err
		}
		if size > maxTotalBytes-total {
			return spec.Err(2, "source distribution exceeds total size limit")
		}
		total += size
		files = append(files, spec.FileRecord{Path: relative, Digest: digest, Size: size, Mode: uint32(info.Mode().Perm())})
		return nil
	})
	return files, err
}
