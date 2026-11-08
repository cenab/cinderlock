package sourceexport

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

// Scheduling mutation at a cancellation boundary makes the filesystem race
// deterministic without sleeps, compiler substitutes, or executing the result.
type mutationContext struct {
	context.Context
	check func()
	done  func()
}

func (c mutationContext) Err() error {
	if c.check != nil {
		c.check()
	}
	return c.Context.Err()
}

func (c mutationContext) Done() <-chan struct{} {
	if c.done != nil {
		c.done()
	}
	return c.Context.Done()
}

func TestCopySelectedRejectsReplacedAncestor(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	destination := filepath.Join(t.TempDir(), "export")
	if err := os.Mkdir(filepath.Join(root, "internal"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, outside, "copied.go", "outside-root-synthetic-private-marker")
	calls := 0
	ctx := mutationContext{Context: context.Background(), check: func() {
		calls++
		if calls == 2 {
			if err := os.Rename(filepath.Join(root, "internal"), filepath.Join(root, "parked")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, "internal")); err != nil {
				t.Fatal(err)
			}
		}
	}}
	if err := copySelected(ctx, root, destination, publicSource); err == nil {
		t.Fatal("replaced directory was accepted")
	}
	if calls < 2 {
		t.Fatal("directory replacement was not scheduled")
	}
	if _, err := os.Lstat(filepath.Join(destination, "internal", "copied.go")); !os.IsNotExist(err) {
		t.Fatal("outside-root content entered source export", err)
	}
}

func TestRootedWalkBoundsDeepDirectories(t *testing.T) {
	root := t.TempDir()
	deep := root
	for range 65 {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := inventory(context.Background(), root); spec.ExitCode(err) != 2 {
		t.Fatal("deep directory tree was not refused", err)
	}
}

func TestCopyRejectsChangedEntryBeforeUsingItsSizeBudget(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "source.go")
	writeFixture(t, directory, "source.go", "small")
	before, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, directory, "source.go", "larger replacement after size admission")
	root, err := openTree(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	destination := filepath.Join(t.TempDir(), "copied")
	if err := copyRegularAt(context.Background(), root, "source.go", destination, before, false); spec.ExitCode(err) != 12 {
		t.Fatal("stale entry size was accepted", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("changed entry was copied using its earlier size budget", err)
	}
}

func TestOfflineBuildCompilesOnlyVerifiedSnapshot(t *testing.T) {
	exported := filepath.Join(t.TempDir(), "export")
	if _, err := Export(context.Background(), smallProject(t), exported, Options{GoBinary: approvedGo(t)}); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(exported, "source", "cmd", "cinderlock", "main.go")
	original, err := os.ReadFile(main)
	if err != nil {
		t.Fatal(err)
	}
	const marker = "UNADMITTED-TRANSIENT-SOURCE-MUST-NOT-BE-COMPILED"
	injected := []byte("package main\nfunc main() { panic(\"" + marker + "\") }\n")
	changed, restored := false, false
	ctx := mutationContext{Context: context.Background(), check: func() {
		if changed && !restored {
			if err := os.WriteFile(main, original, 0644); err != nil {
				t.Fatal(err)
			}
			restored = true
		}
	}, done: func() {
		if changed {
			return
		}
		pcs := make([]uintptr, 32)
		n := runtime.Callers(2, pcs)
		frames := runtime.CallersFrames(pcs[:n])
		starting, inspecting := false, false
		for {
			frame, more := frames.Next()
			starting = starting || frame.Function == "os/exec.(*Cmd).Start"
			inspecting = inspecting || frame.Function == "github.com/cenab/cinderlock/internal/sourceexport.inspectGo"
			if !more {
				break
			}
		}
		if starting && !inspecting {
			if err := os.WriteFile(main, injected, 0644); err != nil {
				t.Fatal(err)
			}
			changed = true
		}
	}}
	binary := filepath.Join(t.TempDir(), "result")
	if err := BuildOffline(ctx, exported, approvedGo(t), binary); err != nil {
		t.Fatal(err)
	}
	if !changed || !restored {
		t.Fatalf("mutation did not span compilation: changed=%v restored=%v", changed, restored)
	}
	if _, err := Verify(context.Background(), exported); err != nil {
		t.Fatal("restored original distribution does not verify", err)
	}
	built, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(built, []byte(marker)) {
		t.Fatal("published binary contains source absent from the admitted inventory")
	}
}

func TestExplicitInputGoPathCannotBecomeExternalAfterSnapshot(t *testing.T) {
	exported := filepath.Join(t.TempDir(), "export")
	manifest, err := Export(context.Background(), smallProject(t), exported, Options{GoBinary: approvedGo(t)})
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	outside, err = filepath.EvalSymlinks(outside)
	if err != nil {
		t.Fatal(err)
	}
	outsideGo := filepath.Join(outside, "bin", "go")
	witness := filepath.Join(t.TempDir(), "outside-go-was-executed")
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	// Both copies delegate to the genuine compiler. Only execution through the
	// substituted outside path writes a witness, independent of build output.
	wrapper := "#!/bin/sh\nif [ \"$0\" = " + quote(outsideGo) + " ]; then printf outside > " + quote(witness) + "; fi\nexec " + quote(approvedGo(t)) + " \"$@\"\n"
	writeFixture(t, outside, "bin/go", wrapper)
	toolDirectory := filepath.Join(exported, "tools", "admitted-go")
	writeFixture(t, toolDirectory, "bin/go", wrapper)
	inputGo := filepath.Join(toolDirectory, "bin", "go")
	for _, file := range []string{outsideGo, inputGo} {
		if err := os.Chmod(file, 0700); err != nil {
			t.Fatal(err)
		}
	}
	manifest.Go.Digest, _, err = hashRegular(context.Background(), inputGo)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Files, err = inventory(context.Background(), exported)
	if err != nil {
		t.Fatal(err)
	}
	data, err := spec.Canonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(exported, "manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	changed := false
	ctx := mutationContext{Context: context.Background(), check: func() {
		if changed {
			return
		}
		pcs := make([]uintptr, 32)
		n := runtime.Callers(2, pcs)
		frames := runtime.CallersFrames(pcs[:n])
		for {
			frame, more := frames.Next()
			if frame.Function == "github.com/cenab/cinderlock/internal/sourceexport.Verify" {
				if err := os.Rename(toolDirectory, toolDirectory+"-parked"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, toolDirectory); err != nil {
					t.Fatal(err)
				}
				changed = true
				return
			}
			if !more {
				return
			}
		}
	}}
	if err := BuildOffline(ctx, exported, inputGo, filepath.Join(t.TempDir(), "result")); err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("tool-directory substitution was not scheduled")
	}
	if _, err := os.Lstat(witness); !os.IsNotExist(err) {
		t.Fatal("an explicit input-relative Go path escaped its verified snapshot", err)
	}
}
