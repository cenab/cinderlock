package modelstage

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
)

const stagingDirectory = ".cinderlock-staging"

type stagingJournal struct {
	base, root *os.Root
	owner      string
	parts      map[string]bool
}

func prepareStaging(root *os.Root, files []spec.FileRecord) (*stagingJournal, error) {
	data, err := Manifest(files)
	if err != nil {
		return nil, err
	}
	owner := spec.Hash(data) + "\n"
	info, err := root.Lstat(stagingDirectory)
	if errors.Is(err, os.ErrNotExist) {
		if err = root.Mkdir(stagingDirectory, 0700); err != nil {
			return nil, err
		}
		info, err = root.Lstat(stagingDirectory)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, spec.Err(14, "model staging journal is not an owned real directory")
	}
	journalRoot, err := root.OpenRoot(stagingDirectory)
	if err != nil {
		return nil, err
	}
	journal := &stagingJournal{base: root, root: journalRoot, owner: owner, parts: map[string]bool{}}
	for _, file := range files {
		journal.parts[partName(file.Path)] = true
	}
	complete := false
	defer func() {
		if !complete {
			journalRoot.Close()
		}
	}()
	entries, err := fs.ReadDir(journalRoot.FS(), ".")
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		file, err := journalRoot.OpenFile("owner", os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return nil, err
		}
		_, err = file.WriteString(owner)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if err = syncRoot(journalRoot); err != nil {
			return nil, err
		}
	}
	if err = journal.checkOwner(); err != nil {
		return nil, err
	}
	entries, err = fs.ReadDir(journalRoot.FS(), ".")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Name() == "owner" {
			continue
		}
		if !journal.parts[entry.Name()] || !entry.Type().IsRegular() {
			return nil, spec.Err(14, "staging journal has unrecognized data; manual reconciliation is required")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil, spec.Err(14, "staging partial file is not regular")
		}
	}
	for _, entry := range entries {
		if entry.Name() != "owner" {
			if err = journalRoot.Remove(entry.Name()); err != nil {
				return nil, err
			}
		}
	}
	if err = syncRoot(journalRoot); err != nil {
		return nil, err
	}
	complete = true
	return journal, nil
}

func partName(name string) string {
	return strings.TrimPrefix(spec.Hash([]byte(name)), "sha256:") + ".part"
}

func (j *stagingJournal) checkOwner() error {
	file, err := j.root.OpenFile("owner", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return spec.Err(14, "model staging owner is missing or unsafe")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(j.owner)) {
		return spec.Err(14, "model staging owner differs from the signed manifest")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(len(j.owner))+1))
	if err != nil || string(data) != j.owner {
		return spec.Err(14, "model staging owner differs from the signed manifest")
	}
	return nil
}

func (j *stagingJournal) finish() error {
	if err := j.checkOwner(); err != nil {
		return err
	}
	entries, err := fs.ReadDir(j.root.FS(), ".")
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0].Name() != "owner" {
		return spec.Err(14, "staging still contains partial or unrecognized files")
	}
	if err = j.root.Remove("owner"); err != nil {
		return err
	}
	if err = j.base.Remove(stagingDirectory); err != nil {
		return err
	}
	return syncRoot(j.base)
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
