package sourceexport

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
)

// Each descended directory has its own stable handle. Path-based walking can
// otherwise follow a replaced ancestor between admitting an entry and reading
// it. Root also refuses symlinks that escape that handle's directory tree.
func openTree(name string) (*os.Root, error) {
	before, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, spec.Err(2, "source export requires a real directory")
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		root.Close()
		return nil, spec.Err(12, "source directory changed while opening")
	}
	return root, nil
}

func walkRooted(ctx context.Context, root *os.Root, selectPath func(string, bool) bool, visit func(*os.Root, string, string, fs.FileInfo) error) error {
	visited := 0
	var descend func(*os.Root, string) error
	descend = func(parent *os.Root, prefix string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		dir, err := parent.Open(".")
		if err != nil {
			return err
		}
		entries, readErr := dir.ReadDir(maxFiles + 1)
		closeErr := dir.Close()
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(entries) > maxFiles {
			return spec.Err(2, "source directory exceeds the supported entry limit")
		}
		slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			visited++
			if visited > maxFiles {
				return spec.Err(2, "source tree exceeds the supported entry limit")
			}
			relative := path.Join(prefix, entry.Name())
			if len(relative) > 4096 || strings.Count(relative, "/") >= 64 {
				return spec.Err(2, "source tree exceeds the supported path or depth limit")
			}
			if !selectPath(relative, entry.IsDir()) {
				continue
			}
			info, err := parent.Lstat(entry.Name())
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 || entry.Type()&os.ModeSymlink != 0 || info.IsDir() != entry.IsDir() {
				return spec.Err(12, "source/toolchain entry changed or is a symlink: %s", relative)
			}
			if !info.IsDir() {
				if err := visit(parent, entry.Name(), relative, info); err != nil {
					return err
				}
				continue
			}
			child, err := parent.OpenRoot(entry.Name())
			if err != nil {
				return err
			}
			opened, statErr := child.Stat(".")
			if statErr != nil || !os.SameFile(info, opened) {
				child.Close()
				return spec.Err(12, "source directory changed while descending")
			}
			err = visit(parent, entry.Name(), relative, info)
			if err == nil {
				err = descend(child, relative)
			}
			closeErr := child.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		}
		return nil
	}
	return descend(root, "")
}

func openRegularAt(root *os.Root, name string, expected fs.FileInfo) (*os.File, fs.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maxFileBytes {
		return nil, nil, spec.Err(2, "source distribution requires bounded regular files")
	}
	if expected != nil && (!os.SameFile(expected, before) || expected.Size() != before.Size() || expected.Mode() != before.Mode() || !expected.ModTime().Equal(before.ModTime())) {
		return nil, nil, spec.Err(12, "source entry changed before opening")
	}
	// Refuse a final symlink and avoid blocking on a regular-file entry replaced
	// by a FIFO before open. The opened descriptor is checked again below.
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		f.Close()
		return nil, nil, spec.Err(12, "source file changed while opening")
	}
	return f, before, nil
}

func unchanged(file *os.File, before fs.FileInfo, n int64) bool {
	after, err := file.Stat()
	return err == nil && n == before.Size() && after.Size() == before.Size() && after.Mode() == before.Mode() && after.ModTime().Equal(before.ModTime())
}
