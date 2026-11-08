package sourceexport

import (
	"bytes"
	"context"
	"io"
	"os"
	"unicode/utf8"

	"github.com/cenab/cinderlock/internal/spec"
)

func validateNotices(ctx context.Context, directory string) error {
	root, err := openTree(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	return validateNoticesAt(ctx, root)
}

func validateNoticesAt(ctx context.Context, root *os.Root) error {
	for _, name := range []string{"LICENSE", "NOTICE"} {
		path := name
		before, err := root.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 1<<20 {
			return spec.Err(2, "Helm root legal notice must be bounded regular text")
		}
		file, opened, err := openRegularAt(root, path, before)
		if err != nil {
			return err
		}
		text, readErr := io.ReadAll(contextReader{ctx, io.LimitReader(file, 1<<20+1)})
		stable := unchanged(file, opened, int64(len(text)))
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if !stable {
			return spec.Err(12, "Helm legal notice changed while reading")
		}
		if len(text) > 1<<20 || len(bytes.TrimSpace(text)) == 0 || !utf8.Valid(text) || bytes.ContainsRune(text, 0) {
			return spec.Err(2, "Helm root legal notice must be nonempty UTF-8 text")
		}
		return nil
	}
	return spec.Err(2, "operator-admitted Helm notices need a root LICENSE or NOTICE text file")
}
