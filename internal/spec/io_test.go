package spec

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadRejectsSpecialFilesWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "document")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { var out map[string]any; done <- Read(path, &out) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as a configuration document")
		}
	case <-time.After(time.Second):
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err = unix.Close(fd); err != nil {
			t.Fatal(err)
		}
		<-done
		t.Fatal("configuration reader blocked on a special file")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"value":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := Read(link, &out); err != nil {
		t.Fatal("regular-file symlinks remain supported:", err)
	}
}

func TestStrictDocuments(t *testing.T) {
	bad := []string{`{"x":1,"x":2}`, `{"x":1.25}`, `{"x":9007199254740992}`, "x: 1\nx: 2\n", "x: &a [1]\ny: *a\n", `{"x":1} {"x":2}`, "x: !!python/object:bad {}"}
	for _, s := range bad {
		var out map[string]any
		if e := Decode([]byte(s), &out); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
	var h Header
	if e := Decode([]byte(`{"unrecognized":true}`), &h); e == nil {
		t.Fatal("unknown field accepted")
	}
}
func TestCanonicalStable(t *testing.T) {
	a, e := CanonicalRaw([]byte(`{"z":2,"a":"<tag>"}`))
	if e != nil {
		t.Fatal(e)
	}
	if string(a) != `{"a":"<tag>","z":2}` {
		t.Fatal(string(a))
	}
	if strings.Contains(string(a), "\\u003c") {
		t.Fatal("not JCS")
	}
}
func TestPaths(t *testing.T) {
	for _, s := range []string{"../a", "/etc/passwd", "a/../b", "a\\b", "a\x00b"} {
		if SafePath(s) {
			t.Fatal(s)
		}
	}
	if !SafePath("models/weights.bin") {
		t.Fatal("valid path rejected")
	}
}

func TestExactFieldNames(t *testing.T) {
	for _, s := range []string{`{"APIVERSION":"x"}`, `{"metadata":{"Application":"x"}}`} {
		var out Header
		if err := Decode([]byte(s), &out); err == nil {
			t.Fatalf("case-ambiguous field accepted: %s", s)
		}
	}
}
func FuzzStrictDecode(f *testing.F) {
	f.Add([]byte(`{"x":1}`))
	f.Add([]byte("x: 1"))
	f.Fuzz(func(t *testing.T, b []byte) { var v any; _ = Decode(b, &v) })
}

func TestWriteReservesTheReadersTrailingNewlineByte(t *testing.T) {
	for _, spare := range []int{0, 1} {
		name := "compact-at-limit"
		if spare == 1 {
			name = "newline-at-limit"
		}
		t.Run(name, func(t *testing.T) {
			document := map[string]string{"value": strings.Repeat("x", MaxDocumentBytes-len(`{"value":""}`)-spare)}
			path := filepath.Join(t.TempDir(), "document.json")
			err := Write(path, document)
			if err != nil && spare == 0 {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("size rejection left an unreadable output file", err)
				}
				return
			}
			if err != nil {
				t.Fatal("readable inclusive-limit document was rejected", err)
			}
			var restored map[string]string
			if err := Read(path, &restored); err != nil || restored["value"] != document["value"] {
				t.Fatal("successful writer produced a document its reader cannot reopen", err)
			}
		})
	}
}
