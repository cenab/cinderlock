package modelstage

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func TestStreamStagesVerifiedBundleWithoutCarrierImage(t *testing.T) {
	content := []byte("native model bytes")
	digest := spec.Hash(content)
	cache := t.TempDir()
	blob, err := bundle.BlobPath(cache, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(blob), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(blob, content, 0600); err != nil {
		t.Fatal(err)
	}
	files := []spec.FileRecord{{Path: "weights/model.bin", Digest: digest, Size: int64(len(content))}}
	v := &bundle.Verified{Root: cache, Index: spec.BundleIndex{Lock: spec.ReleaseLock{Assets: []spec.LockedAsset{{ID: "model", Type: "model-tree", Files: files}}}}}
	var stream bytes.Buffer
	if err = Send(context.Background(), v, "model", &stream); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = Receive(context.Background(), root, "payload", files, &stream); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "payload/weights/model.bin"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("wrong staged model %q: %v", got, err)
	}
	if err = Verify(filepath.Join(root, "payload"), files); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(blob, bytes.Repeat([]byte("x"), len(content)), 0600); err != nil {
		t.Fatal(err)
	}
	if err = Send(context.Background(), v, "model", io.Discard); err == nil {
		t.Fatal("bundle blob modified after verification was streamed as trusted")
	}
}

func TestReceiverResumesOwnedPartialAndPreservesCompletedFiles(t *testing.T) {
	root := t.TempDir()
	content := []byte("complete")
	files := []spec.FileRecord{{Path: "first.bin", Digest: spec.Hash(content), Size: int64(len(content))}, {Path: "second.bin", Digest: spec.Hash(content), Size: int64(len(content))}}
	if err := os.WriteFile(filepath.Join(root, "first.bin"), content, 0600); err != nil {
		t.Fatal(err)
	}
	when := time.Unix(1500000000, 0)
	if err := os.Chtimes(filepath.Join(root, "first.bin"), when, when); err != nil {
		t.Fatal(err)
	}
	bound, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := prepareStaging(bound, files)
	if err != nil {
		t.Fatal(err)
	}
	// This is the exact on-disk state after a receiver dies mid-file: an owned
	// journal, one partial file, and a previously published complete file.
	if err = os.WriteFile(filepath.Join(root, stagingDirectory, partName("second.bin")), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	journal.root.Close()
	bound.Close()
	var stream bytes.Buffer
	tw := tar.NewWriter(&stream)
	for _, file := range files {
		if err = tw.WriteHeader(&tar.Header{Name: file.Path, Typeflag: tar.TypeReg, Mode: 0600, Size: file.Size}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = Receive(context.Background(), root, "", files, &stream); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "first.bin"))
	if err != nil || !info.ModTime().Equal(when) {
		t.Fatalf("completed file was rewritten: %v %v", info, err)
	}
	if err = Verify(root, files); err != nil {
		t.Fatal(err)
	}
}

func TestReceiverPreservesUnrecognizedStagingData(t *testing.T) {
	content := []byte("locked")
	files := []spec.FileRecord{{Path: "model.bin", Digest: spec.Hash(content), Size: int64(len(content))}}
	for _, mutation := range []string{"unknown-file", "wrong-owner", "symlink-part"} {
		t.Run(mutation, func(t *testing.T) {
			root := t.TempDir()
			bound, err := os.OpenRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := prepareStaging(bound, files)
			if err != nil {
				t.Fatal(err)
			}
			journal.root.Close()
			bound.Close()
			name := filepath.Join(root, stagingDirectory, "customer-data")
			switch mutation {
			case "unknown-file":
				err = os.WriteFile(name, content, 0600)
			case "wrong-owner":
				name = filepath.Join(root, stagingDirectory, "owner")
				err = os.WriteFile(name, []byte("another release"), 0600)
			case "symlink-part":
				name = filepath.Join(root, stagingDirectory, partName("model.bin"))
				err = os.Symlink("/outside", name)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = Receive(context.Background(), root, "", files, bytes.NewReader(archive(t, "model.bin", tar.TypeReg, content))); err == nil {
				t.Fatal("unrecognized staging state accepted")
			}
			if _, err = os.Lstat(name); err != nil {
				t.Fatal("unrecognized data removed", err)
			}
		})
	}
}

func TestReceiverBoundsArchiveMetadataAndSupportsLongSignedNames(t *testing.T) {
	name := strings.Repeat("a", 200) + "/" + strings.Repeat("b", 200) + "/weights.bin"
	content := []byte("locked")
	files := []spec.FileRecord{{Path: name, Digest: spec.Hash(content), Size: int64(len(content))}}
	var valid bytes.Buffer
	tw := tar.NewWriter(&valid)
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Format: tar.FormatGNU, Mode: 0600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Receive(context.Background(), t.TempDir(), "", files, bytes.NewReader(valid.Bytes())); err != nil {
		t.Fatal("long signed regular path rejected", err)
	}
	// tar permits archive metadata records before files. Limit the entire
	// transport, including records hidden by archive/tar's Next method.
	if valid.Bytes()[156] != tar.TypeGNULongName {
		t.Fatal("fixture has no GNU name extension")
	}
	metadata := bytes.Repeat(valid.Bytes()[:1024], 6)
	counted := &countReader{reader: io.MultiReader(bytes.NewReader(metadata), bytes.NewReader(valid.Bytes()))}
	if err := Receive(context.Background(), t.TempDir(), "", files, counted); err == nil {
		t.Fatal("unbounded archive metadata accepted")
	}
	if counted.bytes > int64(len(content))+4096+1024 {
		t.Fatalf("read beyond signed transport bound: %d", counted.bytes)
	}
}

type countReader struct {
	reader io.Reader
	bytes  int64
}

func (r *countReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytes += int64(n)
	return n, err
}

func archive(t *testing.T, name string, kind byte, content []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: kind, Mode: 0600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestReceiverRefusesCorruptionWithoutPublishing(t *testing.T) {
	root := t.TempDir()
	correct := []byte("locked")
	files := []spec.FileRecord{{Path: "model.bin", Digest: spec.Hash(correct), Size: int64(len(correct))}}
	if err := Receive(context.Background(), root, "", files, bytes.NewReader(archive(t, "model.bin", tar.TypeReg, []byte("broken")))); err == nil {
		t.Fatal("corrupt model accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("corrupt or temporary file published", entries)
	}
	if err = Receive(context.Background(), root, "", files, bytes.NewReader(archive(t, "model.bin", tar.TypeReg, correct))); err != nil {
		t.Fatal(err)
	}
	if err = Receive(context.Background(), root, "", files, bytes.NewReader(archive(t, "model.bin", tar.TypeReg, correct))); err != nil {
		t.Fatal("matching existing file not idempotent", err)
	}
	if err = os.WriteFile(filepath.Join(root, "model.bin"), []byte("wrong!"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = Receive(context.Background(), root, "", files, bytes.NewReader(archive(t, "model.bin", tar.TypeReg, correct))); err == nil {
		t.Fatal("existing corrupt data overwritten")
	}
	got, err := os.ReadFile(filepath.Join(root, "model.bin"))
	if err != nil || string(got) != "wrong!" {
		t.Fatal("existing data lost", err)
	}
}

func TestReceiverRejectsUnlistedAndIncompleteInput(t *testing.T) {
	content := []byte("locked")
	files := []spec.FileRecord{{Path: "model.bin", Digest: spec.Hash(content), Size: int64(len(content))}}
	valid := archive(t, "model.bin", tar.TypeReg, content)
	for name, input := range map[string][]byte{"missing": archive(t, "other.bin", tar.TypeReg, content), "truncated": valid[:515], "trailing": append(append([]byte{}, valid...), []byte("unverified")...), "escape": archive(t, "../escape", tar.TypeReg, content)} {
		t.Run(name, func(t *testing.T) {
			if err := Receive(context.Background(), t.TempDir(), "", files, bytes.NewReader(input)); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	for _, subpath := range []string{"..", "../escape", "/absolute", ".", "a/../b"} {
		if err := Receive(context.Background(), t.TempDir(), subpath, files, bytes.NewReader(valid)); err == nil {
			t.Fatal("invalid subdirectory accepted", subpath)
		}
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "payload")); err != nil {
		t.Fatal(err)
	}
	if err := Receive(context.Background(), root, "payload", files, bytes.NewReader(valid)); err == nil {
		t.Fatal("symlink subdirectory accepted")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("write escaped model mount", entries, err)
	}
	if err := os.Mkdir(filepath.Join(outside, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "nested/model.bin"), content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAt(root, "payload/nested", files); err == nil {
		t.Fatal("verifier followed symlink in selected subdirectory parent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Receive(ctx, t.TempDir(), "", files, bytes.NewReader(valid)); err == nil {
		t.Fatal("cancelled transfer accepted")
	}
	if _, err := Manifest([]spec.FileRecord{{Path: "a", Digest: spec.Hash(nil)}, {Path: "a/b", Digest: spec.Hash(nil)}}); err == nil {
		t.Fatal("file/directory collision accepted")
	}
	if err := Receive(context.Background(), t.TempDir(), "", files, strings.NewReader("")); err == nil {
		t.Fatal("empty input accepted")
	}
}
