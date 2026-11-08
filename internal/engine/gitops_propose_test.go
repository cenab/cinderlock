package engine

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

type proposalRepository struct {
	t    *testing.T
	dir  string
	git  string
	head string
}

func newProposalRepository(t *testing.T, body []byte, initOptions ...string) proposalRepository {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	r := proposalRepository{t: t, dir: directory, git: git}
	r.command(nil, append([]string{"init", "--initial-branch=fixture"}, initOptions...)...)
	if err = os.WriteFile(filepath.Join(r.dir, "application.yaml"), body, 0600); err != nil {
		t.Fatal(err)
	}
	r.command(nil, "add", "--", "application.yaml")
	r.command(nil, "commit", "-m", "Fixture base")
	r.head = string(bytes.TrimSpace(r.command(nil, "rev-parse", "HEAD")))
	return r
}

func (r proposalRepository) command(input []byte, args ...string) []byte {
	r.t.Helper()
	base := []string{"--no-pager", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.DevNull, "-c", "core.fsmonitor=false"}
	command := exec.Command(r.git, append(base, args...)...)
	command.Dir = r.dir
	command.Env = []string{"PATH=" + filepath.Dir(r.git), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "LANG=C", "LC_ALL=C"}
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		r.t.Fatalf("fixture Git %v failed: %v: %s", args, err, output)
	}
	return output
}

func repositoryBytes(t *testing.T, directory string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var body []byte
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			body = []byte(target)
		} else {
			body, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		files[name] = fmt.Sprintf("%s:%s", info.Mode(), body)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestGitOpsSourceProposalRejectsDirtyWorkingBytes(t *testing.T) {
	r := newProposalRepository(t, []byte("kind: ConfigMap\ndata: {state: base}\n"))
	if err := os.WriteFile(filepath.Join(r.dir, "application.yaml"), []byte("kind: ConfigMap\ndata: {state: unreviewed}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before := repositoryBytes(t, r.dir)
	_, err := ProposeGitOpsSource(context.Background(), r.dir, r.head, "application.yaml", []byte("kind: ConfigMap\ndata: {state: desired}\n"))
	if spec.ExitCode(err) != 11 {
		t.Fatalf("dirty source admitted to an exact-base proposal: %v", err)
	}
	if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
		t.Fatal("rejected proposal changed repository files or metadata")
	}
}

func TestGitOpsSourceProposalProducesApplicablePatchWithoutRepositoryWrites(t *testing.T) {
	for _, tc := range []struct {
		name            string
		before, desired []byte
		initOptions     []string
	}{
		{"normal", []byte("kind: ConfigMap\ndata: {state: base}\n"), []byte("kind: ConfigMap\ndata: {state: desired}\n"), nil},
		{"no-newline", []byte("kind: ConfigMap"), []byte("kind: Secret\ndata: {}"), nil},
		{"empty-base", nil, []byte("kind: ConfigMap\n"), nil},
		{"sha256", []byte("kind: ConfigMap\n"), []byte("kind: Secret\n"), []string{"--object-format=sha256"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newProposalRepository(t, tc.before, tc.initOptions...)
			// Unrelated files need not be clean; the proposal only replaces this exact target.
			if err := os.WriteFile(filepath.Join(r.dir, "unrelated.txt"), []byte("local work"), 0600); err != nil {
				t.Fatal(err)
			}
			before := repositoryBytes(t, r.dir)
			change, err := ProposeGitOpsSource(context.Background(), r.dir, r.head, "application.yaml", tc.desired)
			if err != nil {
				t.Fatal(err)
			}
			blob := string(bytes.TrimSpace(r.command(nil, "rev-parse", r.head+":application.yaml")))
			if change.Head != r.head || change.Path != "application.yaml" || change.Repository != r.dir || change.BaseBlob != blob || change.BaseDigest != spec.Hash(tc.before) || change.ManifestDigest != spec.Hash(tc.desired) || change.PatchDigest != spec.Hash([]byte(change.Patch)) {
				t.Fatal("proposal lost its exact source or desired-state binding", change)
			}
			if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
				t.Fatal("proposal changed source/index/objects/refs")
			}
			// Applying is confined to this disposable test repository, after proving proposal purity.
			r.command([]byte(change.Patch), "apply", "--check", "-")
			r.command([]byte(change.Patch), "apply", "-")
			if actual, err := os.ReadFile(filepath.Join(r.dir, "application.yaml")); err != nil || !bytes.Equal(actual, tc.desired) {
				t.Fatal("reviewable patch did not produce the exact desired file", err)
			}
		})
	}
	// A reviewed no-op remains inert and still binds the exact existing bytes.
	body := []byte("kind: ConfigMap\n")
	r := newProposalRepository(t, body)
	change, err := ProposeGitOpsSource(context.Background(), r.dir, r.head, "application.yaml", body)
	if err != nil || change.Patch != "" || change.BaseDigest != spec.Hash(body) || change.ManifestDigest != spec.Hash(body) {
		t.Fatal("no-op proposal was not exact", change, err)
	}
}

func TestGitOpsSourceProposalRejectsUnsafeOrChangedSource(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, proposalRepository, *string, *string, *[]byte)
	}{
		{"stale-head", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			*head = strings.Repeat("a", len(r.head))
		}},
		{"revision-label", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) { *head = "HEAD" }},
		{"staged-target", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			mustWriteProposalFile(t, filepath.Join(r.dir, *path), []byte("staged: true\n"))
			r.command(nil, "add", "--", *path)
		}},
		{"untracked-target", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			*path = "untracked.yaml"
			mustWriteProposalFile(t, filepath.Join(r.dir, *path), []byte("kind: Secret\n"))
		}},
		{"target-symlink", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			mustWriteProposalFile(t, filepath.Join(r.dir, "other.yaml"), []byte("kind: Secret\n"))
			if err := os.Remove(filepath.Join(r.dir, *path)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("other.yaml", filepath.Join(r.dir, *path)); err != nil {
				t.Fatal(err)
			}
		}},
		{"parent-symlink", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			if err := os.Symlink(r.dir, filepath.Join(r.dir, "linked")); err != nil {
				t.Fatal(err)
			}
			*path = "linked/application.yaml"
		}},
		{"path-escape", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			*path = "../application.yaml"
		}},
		{"metadata-path", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			*path = ".git/application.yaml"
		}},
		{"executable-target", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			r.command(nil, "update-index", "--chmod=+x", "--", *path)
			r.command(nil, "commit", "-m", "Executable fixture")
			*head = string(bytes.TrimSpace(r.command(nil, "rev-parse", "HEAD")))
		}},
		{"working-mode-change", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			if err := os.Chmod(filepath.Join(r.dir, *path), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"binary-target", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			mustWriteProposalFile(t, filepath.Join(r.dir, *path), []byte("kind:\x00value\n"))
			r.command(nil, "add", "--", *path)
			r.command(nil, "commit", "-m", "Binary fixture")
			*head = string(bytes.TrimSpace(r.command(nil, "rev-parse", "HEAD")))
		}},
		{"invalid-desired", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) { *desired = []byte{0xff} }},
		{"oversized-desired", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			*desired = bytes.Repeat([]byte{'x'}, maxGitOpsFileBytes+1)
		}},
		{"working-attributes", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			mustWriteProposalFile(t, filepath.Join(r.dir, ".gitattributes"), []byte("*.yaml -text\n"))
		}},
		{"head-attributes", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			mustWriteProposalFile(t, filepath.Join(r.dir, ".gitattributes"), []byte("*.yaml -text\n"))
			r.command(nil, "add", "--", ".gitattributes")
			r.command(nil, "commit", "-m", "Attribute fixture")
			*head = string(bytes.TrimSpace(r.command(nil, "rev-parse", "HEAD")))
			if err := os.Remove(filepath.Join(r.dir, ".gitattributes")); err != nil {
				t.Fatal(err)
			}
		}},
		{"index-attributes", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			mustWriteProposalFile(t, filepath.Join(r.dir, ".gitattributes"), []byte("*.yaml -text\n"))
			r.command(nil, "add", "--", ".gitattributes")
			if err := os.Remove(filepath.Join(r.dir, ".gitattributes")); err != nil {
				t.Fatal(err)
			}
		}},
		{"config-include", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			r.command(nil, "config", "include.path", "/should-not-be-read")
		}},
		{"bom-config-include", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			config := filepath.Join(r.dir, ".git", "config")
			body, err := os.ReadFile(config)
			if err != nil {
				t.Fatal(err)
			}
			mustWriteProposalFile(t, config, append([]byte("\xef\xbb\xbf[include]\npath = /should-not-be-read\n"), body...))
		}},
		{"alternate-objects", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			mustWriteProposalFile(t, filepath.Join(r.dir, ".git", "objects", "info", "alternates"), []byte("/should-not-be-read\n"))
		}},
		{"external-git-directory", func(t *testing.T, r proposalRepository, head, path *string, desired *[]byte) {
			if err := os.Rename(filepath.Join(r.dir, ".git"), filepath.Join(r.dir, "actual-git")); err != nil {
				t.Fatal(err)
			}
			mustWriteProposalFile(t, filepath.Join(r.dir, ".git"), []byte("gitdir: actual-git\n"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newProposalRepository(t, []byte("kind: ConfigMap\n"))
			head, target, desired := r.head, "application.yaml", []byte("kind: Secret\n")
			tc.change(t, r, &head, &target, &desired)
			before := repositoryBytes(t, r.dir)
			if _, err := ProposeGitOpsSource(context.Background(), r.dir, head, target, desired); err == nil {
				t.Fatal("unsafe or changed source admitted")
			}
			if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
				t.Fatal("rejection changed source repository")
			}
		})
	}
}

func mustWriteProposalFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestGitOpsSourceProposalIsolatesGitConfigurationAndHelpers(t *testing.T) {
	r := newProposalRepository(t, []byte("kind: ConfigMap\n"))
	helper := filepath.Join(t.TempDir(), "helper")
	sentinel := helper + ".executed"
	mustWriteProposalFile(t, helper, []byte("#!/bin/sh\nprintf invoked > \"$0.executed\"\nexit 1\n"))
	if err := os.Chmod(helper, 0700); err != nil {
		t.Fatal(err)
	}
	r.command(nil, "config", "core.fsmonitor", helper)
	r.command(nil, "config", "core.hooksPath", helper)
	r.command(nil, "config", "diff.external", helper)
	r.command(nil, "config", "filter.custom.process", helper)
	t.Setenv("GIT_EXTERNAL_DIFF", helper)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
	t.Setenv("GIT_CONFIG_VALUE_0", helper)
	t.Setenv("GIT_OBJECT_DIRECTORY", "/should-not-be-used")
	before := repositoryBytes(t, r.dir)
	if _, err := ProposeGitOpsSource(context.Background(), r.dir, r.head, "application.yaml", []byte("kind: Secret\n")); err != nil {
		t.Fatal("repository or inherited executable helpers affected a local object read", err)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatal("executable Git helper ran", err)
	}
	if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
		t.Fatal("Git reads changed repository metadata")
	}
}

func TestGitOpsProposalWriterIsPrivateExclusiveAndOutsideSource(t *testing.T) {
	r := newProposalRepository(t, []byte("kind: ConfigMap\n"))
	change, err := ProposeGitOpsSource(context.Background(), r.dir, r.head, "application.yaml", []byte("kind: Secret\n"))
	if err != nil {
		t.Fatal(err)
	}
	proposal := GitOpsProposal{Header: spec.NewHeader("GitOpsProposal"), Source: change, ApplicationAcceptance: "not_established"}
	out := filepath.Join(t.TempDir(), "proposal.json")
	before := repositoryBytes(t, r.dir)
	if err = WriteGitOpsProposal(out, proposal); err != nil {
		t.Fatal(err)
	}
	var actual GitOpsProposal
	if err = spec.Read(out, &actual); err != nil || !reflect.DeepEqual(actual, proposal) {
		t.Fatal("proposal did not roundtrip", actual, err)
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("proposal wasn't private", err)
	}
	if err = WriteGitOpsProposal(out, proposal); err == nil {
		t.Fatal("proposal overwrote an existing review artifact")
	}
	inside := filepath.Join(r.dir, "proposal.json")
	if err = WriteGitOpsProposal(inside, proposal); spec.ExitCode(err) != 16 {
		t.Fatal("proposal output entered source repository", err)
	}
	linked := filepath.Join(t.TempDir(), "linked.json")
	if err = os.Symlink(inside, linked); err != nil {
		t.Fatal(err)
	}
	if err = WriteGitOpsProposal(linked, proposal); err == nil {
		t.Fatal("proposal followed a symlink output")
	}
	linkedDirectory := filepath.Join(t.TempDir(), "linked")
	if err = os.Symlink(r.dir, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err = GitOpsPreparationPath(r.dir, filepath.Join(linkedDirectory, "scratch")); spec.ExitCode(err) != 16 {
		t.Fatal("preparation escaped through a symlink parent", err)
	}
	if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
		t.Fatal("proposal output changed source repository")
	}
}
