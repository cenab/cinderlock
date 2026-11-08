package modelstage

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
)

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

type streamReader struct {
	reader    io.Reader
	remaining int64
}

func (r *streamReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, spec.Err(14, "model stream exceeds its signed payload and bounded metadata budget")
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func Send(ctx context.Context, v *bundle.Verified, assetID string, writer io.Writer) error {
	asset, err := v.Asset(assetID)
	if err != nil {
		return err
	}
	if asset.Type == "image" {
		return spec.Err(12, "model stream cannot contain an image graph")
	}
	if _, err = Manifest(asset.Files); err != nil {
		return err
	}
	root, err := os.OpenRoot(v.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	files := append([]spec.FileRecord(nil), asset.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	tw := tar.NewWriter(writer)
	for _, record := range files {
		if err = ctx.Err(); err != nil {
			return err
		}
		file, err := root.OpenFile("blobs/sha256/"+strings.TrimPrefix(record.Digest, "sha256:"), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != record.Size {
			file.Close()
			return spec.Err(12, "model payload type or size differs from its signed record")
		}
		if err = tw.WriteHeader(&tar.Header{Name: record.Path, Typeflag: tar.TypeReg, Mode: 0600, Size: record.Size, Format: tar.FormatGNU}); err != nil {
			file.Close()
			return err
		}
		hash := sha256.New()
		_, err = io.CopyBuffer(io.MultiWriter(tw, hash), io.LimitReader(contextReader{ctx, file}, record.Size), make([]byte, 64<<10))
		after, statErr := file.Stat()
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if statErr != nil || after.Size() != info.Size() || after.ModTime() != info.ModTime() || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != record.Digest {
			return spec.Err(12, "model payload changed or differs from its signed record")
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return tw.Close()
}

// Receive publishes only hash-verified files, never overwrites existing bytes,
// and verifies the complete selected tree before reporting success.
func Receive(ctx context.Context, directory, subPath string, files []spec.FileRecord, reader io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := Manifest(files); err != nil {
		return err
	}
	budget := int64(1024) + int64(len(files))*4096
	for _, file := range files {
		budget += file.Size
	}
	reader = &streamReader{reader: contextReader{ctx, reader}, remaining: budget}
	if subPath != "" && (subPath == "." || !spec.SafePath(subPath)) {
		return spec.Err(12, "model subdirectory is not confined")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return spec.Err(14, "model mount must be a real directory")
	}
	base, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer base.Close()
	root := base
	if subPath != "" {
		if err = ensureDirectories(base, subPath); err != nil {
			return err
		}
		root, err = base.OpenRoot(subPath)
		if err != nil {
			return err
		}
		defer root.Close()
	}
	expected := map[string]spec.FileRecord{}
	journal, err := prepareStaging(root, files)
	if err != nil {
		return err
	}
	defer journal.root.Close()
	finished := false
	defer func() {
		if !finished {
			_ = journal.finish()
		}
	}()
	for _, record := range files {
		expected[record.Path] = record
	}
	seen := map[string]bool{}
	tr := tar.NewReader(reader)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return spec.Err(14, "model stream is incomplete or malformed")
		}
		record, ok := expected[header.Name]
		if !ok || seen[header.Name] || header.Typeflag != tar.TypeReg || header.Size != record.Size || header.Linkname != "" {
			return spec.Err(14, "model stream differs from the signed file list")
		}
		if err = receiveFile(ctx, root, journal, record, tr); err != nil {
			return err
		}
		seen[record.Path] = true
	}
	if len(seen) != len(expected) {
		return spec.Err(14, "model stream is missing signed files")
	}
	var extra [1]byte
	if n, err := (contextReader{ctx, reader}).Read(extra[:]); n != 0 || err != io.EOF {
		return spec.Err(14, "model stream has trailing data or no confirmed end")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = journal.finish(); err != nil {
		return err
	}
	finished = true
	return verifyRoot(root, files)
}

func ensureDirectories(root *os.Root, directory string) error {
	if directory == "." {
		return nil
	}
	prefix := ""
	for _, part := range strings.Split(directory, "/") {
		if prefix != "" {
			prefix += "/"
		}
		prefix += part
		info, err := root.Lstat(prefix)
		if errors.Is(err, os.ErrNotExist) {
			if err = root.Mkdir(prefix, 0700); err != nil {
				return err
			}
			info, err = root.Lstat(prefix)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return spec.Err(14, "model destination parent is not a real directory")
		}
	}
	return nil
}

func receiveFile(ctx context.Context, root *os.Root, journal *stagingJournal, record spec.FileRecord, reader io.Reader) error {
	if err := ensureDirectories(root, path.Dir(record.Path)); err != nil {
		return err
	}
	existing, err := root.Lstat(record.Path)
	if err == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 {
			return spec.Err(14, "existing model path is not a regular file")
		}
		if err = verifyFile(root, record); err != nil {
			return err
		}
		return copyRecord(ctx, io.Discard, reader, record)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary := partName(record.Path)
	file, err := journal.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer func() { file.Close(); journal.root.Remove(temporary) }()
	if err = copyRecord(ctx, file, reader, record); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = root.Link(stagingDirectory+"/"+temporary, record.Path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if err = verifyFile(root, record); err != nil {
			return err
		}
	}
	if err = journal.root.Remove(temporary); err != nil {
		return err
	}
	parent, err := root.Open(path.Dir(record.Path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func copyRecord(ctx context.Context, writer io.Writer, reader io.Reader, record spec.FileRecord) error {
	hash := sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(writer, hash), io.LimitReader(contextReader{ctx, reader}, record.Size), make([]byte, 64<<10))
	if err != nil {
		return err
	}
	if n != record.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != record.Digest {
		return spec.Err(14, "received model bytes differ from signed hash or size")
	}
	return ctx.Err()
}
