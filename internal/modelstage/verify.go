package modelstage

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
)

const ManifestLimit = 512 * 1024

func Manifest(files []spec.FileRecord) ([]byte, error) {
	if len(files) == 0 {
		return nil, spec.Err(10, "model verification requires a nonempty signed file manifest")
	}
	seen := map[string]bool{}
	var total int64
	for _, file := range files {
		if file.Path == stagingDirectory || strings.HasPrefix(file.Path, stagingDirectory+"/") {
			return nil, spec.Err(12, "model payload uses the reserved staging journal path")
		}
		if file.Path == "" || len(file.Path) > 512 || path.Clean(file.Path) != file.Path || path.IsAbs(file.Path) || strings.ContainsAny(file.Path, "\\:\x00") || file.Path == "." || file.Path == ".." || strings.HasPrefix(file.Path, "../") {
			return nil, spec.Err(12, "model manifest path is not a confined relative file")
		}
		for _, c := range file.Path {
			if c < 32 || c > 126 {
				return nil, spec.Err(12, "model manifest path has unsupported characters")
			}
		}
		if file.Size < 0 || file.Size == math.MaxInt64 || !strings.HasPrefix(file.Digest, "sha256:") || len(file.Digest) != 71 {
			return nil, spec.Err(12, "model manifest needs exact SHA256 hashes and bounded file sizes")
		}
		if _, err := hex.DecodeString(file.Digest[7:]); err != nil || strings.ToLower(file.Digest) != file.Digest || seen[file.Path] {
			return nil, spec.Err(12, "model manifest contains an invalid digest or duplicate file")
		}
		seen[file.Path] = true
		if file.Size > math.MaxInt64-total {
			return nil, spec.Err(12, "model manifest byte total exceeds supported integer range")
		}
		total += file.Size
	}
	if total > math.MaxInt64-1024-int64(len(files))*4096 {
		return nil, spec.Err(12, "model stream with bounded archive metadata exceeds supported integer range")
	}
	for _, file := range files {
		for parent := path.Dir(file.Path); parent != "."; parent = path.Dir(parent) {
			if seen[parent] {
				return nil, spec.Err(12, "model file conflicts with a parent directory")
			}
		}
	}
	data, err := spec.Canonical(files)
	if err != nil {
		return nil, err
	}
	if len(data) > ManifestLimit {
		return nil, spec.Err(10, "model manifest exceeds the supported 512 KiB verification profile")
	}
	return data, nil
}

// Verify checks the entire regular-file tree against the signed manifest.
// The publisher must be quiescent; this does not attest a malicious node.
func Verify(directory string, files []spec.FileRecord) error {
	return VerifyAt(directory, "", files)
}

// VerifyAt selects an existing confined subdirectory without following symlinks
// in its parent path. The base directory is the actual admitted volume mount.
func VerifyAt(directory, subPath string, files []spec.FileRecord) error {
	if _, err := Manifest(files); err != nil {
		return err
	}
	if subPath != "" && (subPath == "." || !spec.SafePath(subPath)) {
		return spec.Err(12, "model verification subdirectory is not confined")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return spec.Err(14, "model root must be an existing real directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	if subPath != "" {
		prefix := ""
		for _, part := range strings.Split(subPath, "/") {
			if prefix != "" {
				prefix += "/"
			}
			prefix += part
			info, err := root.Lstat(prefix)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return spec.Err(14, "model verification parent is not an existing real directory")
			}
		}
		selected, err := root.OpenRoot(subPath)
		if err != nil {
			return err
		}
		defer selected.Close()
		return verifyRoot(selected, files)
	}
	return verifyRoot(root, files)
}

func verifyRoot(root *os.Root, files []spec.FileRecord) error {
	expected := map[string]spec.FileRecord{}
	directories := map[string]bool{".": true}
	for _, file := range files {
		expected[file.Path] = file
		for parent := path.Dir(file.Path); parent != "."; parent = path.Dir(parent) {
			directories[parent] = true
		}
	}
	seen := map[string]bool{}
	entries := 0
	err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > len(expected)+len(directories) {
			return spec.Err(14, "model directory contains unlisted entries")
		}
		if entry.IsDir() {
			if !directories[name] {
				return spec.Err(14, "model directory contains an unlisted directory")
			}
			return nil
		}
		record, ok := expected[name]
		if !ok || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return spec.Err(14, "model directory contains an unlisted or non-regular file")
		}
		if err := verifyFile(root, record); err != nil {
			return err
		}
		seen[name] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return spec.Err(14, "model directory is missing signed files")
	}
	return nil
}

func verifyFile(root *os.Root, record spec.FileRecord) error {
	file, err := root.OpenFile(record.Path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != record.Size {
		return spec.Err(14, "model file size or type differs from signed manifest")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, record.Size+1))
	if err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil || n != record.Size || after.Size() != before.Size() || after.ModTime() != before.ModTime() || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != record.Digest {
		return spec.Err(14, "model bytes differ from signed manifest or changed during verification")
	}
	return nil
}
