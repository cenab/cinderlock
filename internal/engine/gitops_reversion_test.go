package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestObserveGitOpsReversionRestoreCommit(t *testing.T) {
	reviewed := []byte("kind: ConfigMap\ndata: {state: reviewed}\n")
	previousBody := []byte("kind: ConfigMap\ndata: {state: previous}\n")
	r := newProposalRepository(t, reviewed)
	restored := r.head
	mustWriteProposalFile(t, filepath.Join(r.dir, "application.yaml"), previousBody)
	mustWriteProposalFile(t, filepath.Join(r.dir, "unrelated.txt"), []byte("retained change\n"))
	r.command(nil, "add", "--", "application.yaml", "unrelated.txt")
	r.command(nil, "commit", "-m", "Fixture previous source")
	previous := strings.TrimSpace(string(r.command(nil, "rev-parse", "HEAD")))
	mustWriteProposalFile(t, filepath.Join(r.dir, "application.yaml"), reviewed)
	r.command(nil, "add", "--", "application.yaml")
	r.command(nil, "commit", "-m", "Fixture file restoration")
	accepted := strings.TrimSpace(string(r.command(nil, "rev-parse", "HEAD")))
	contract := &GitOpsSourceReversion{Repository: r.dir, PreviousRevision: previous, RestoredRevision: restored}
	before := repositoryBytes(t, r.dir)
	facts, err := ObserveGitOpsReversion(context.Background(), contract, accepted, "application.yaml", reviewed)
	if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
		t.Fatal("observation changed repository or .git bytes")
	}
	if err != nil {
		t.Fatal(err)
	}
	if facts.AcceptedRevision != accepted || facts.PreviousRevision != previous || facts.RestoredRevision != restored || facts.Path != "application.yaml" || facts.PreviousDigest != spec.Hash(previousBody) || facts.ManifestDigest != spec.Hash(reviewed) {
		t.Fatal("observation lost its exact commit, path, or byte bindings", facts)
	}
}

func TestObserveGitOpsReversionDirectReset(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		t.Run(format, func(t *testing.T) {
			reviewed := []byte("kind: ConfigMap\ndata: {state: reviewed}\n")
			previousBody := []byte("kind: ConfigMap\ndata: {state: previous}\n")
			r := newProposalRepository(t, reviewed, "--object-format="+format)
			restored := r.head
			previous := commitReversionFile(t, r, previousBody)
			r.command(nil, "reset", "--hard", restored)
			contract := &GitOpsSourceReversion{Repository: r.dir, PreviousRevision: previous, RestoredRevision: restored}
			before := repositoryBytes(t, r.dir)
			facts, err := ObserveGitOpsReversion(context.Background(), contract, restored, "application.yaml", reviewed)
			if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
				t.Fatal("direct-reset observation changed repository or .git bytes")
			}
			if err != nil {
				t.Fatal(err)
			}
			if facts.AcceptedRevision != restored || facts.RestoredRevision != restored || facts.PreviousRevision != previous || facts.Path != "application.yaml" || facts.PreviousDigest != spec.Hash(previousBody) || facts.ManifestDigest != spec.Hash(reviewed) {
				t.Fatal("direct-reset observation lost its exact bindings", facts)
			}
		})
	}
}

func TestObserveGitOpsReversionRejectsInvalidEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   int
		change func(*testing.T, proposalRepository, *GitOpsSourceReversion, *string, *string, *[]byte)
	}{
		{"restored-bytes-differ", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			c.RestoredRevision = c.PreviousRevision
		}},
		{"previous-bytes-identical", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			c.PreviousRevision = c.RestoredRevision
		}},
		{"restored-is-newer-than-previous", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			c.RestoredRevision = *accepted
		}},
		{"restored-on-sibling-branch", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			r.command(nil, "checkout", "--detach", c.RestoredRevision)
			mustWriteProposalFile(t, filepath.Join(r.dir, "sibling.txt"), []byte("sibling\n"))
			r.command(nil, "add", "--", "sibling.txt")
			r.command(nil, "commit", "-m", "Fixture sibling")
			c.RestoredRevision = strings.TrimSpace(string(r.command(nil, "rev-parse", "HEAD")))
			r.command(nil, "checkout", "--detach", *accepted)
		}},
		{"previous-not-ancestor-of-accepted", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			r.command(nil, "checkout", "--detach", c.RestoredRevision)
			c.PreviousRevision = commitReversionFile(t, r, []byte("private: sibling-previous\n"))
			r.command(nil, "checkout", "--detach", *accepted)
		}},
		{"stale-current-head", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			*accepted = c.RestoredRevision
		}},
		{"clean-current-bytes-differ", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			*accepted = commitReversionFile(t, r, []byte("private: current-unreviewed\n"))
		}},
		{"dirty-working-file", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			mustWriteProposalFile(t, filepath.Join(r.dir, *path), []byte("private: dirty-working\n"))
		}},
		{"dirty-index", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			mustWriteProposalFile(t, filepath.Join(r.dir, *path), []byte("private: dirty-index\n"))
			r.command(nil, "add", "--", *path)
			mustWriteProposalFile(t, filepath.Join(r.dir, *path), *reviewed)
		}},
		{"working-symlink", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			if err := os.Remove(filepath.Join(r.dir, *path)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("private-source-target", filepath.Join(r.dir, *path)); err != nil {
				t.Fatal(err)
			}
		}},
		{"working-executable", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			if err := os.Chmod(filepath.Join(r.dir, *path), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"working-attributes", 10, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			mustWriteProposalFile(t, filepath.Join(r.dir, ".gitattributes"), []byte("*.yaml -text\n"))
		}},
		{"missing-repository", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			c.Repository = filepath.Join(r.dir, "private-config-token")
		}},
		{"config-include", 10, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			r.command(nil, "config", "include.path", "/private-config-token")
		}},
		{"malformed-config", 10, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			mustWriteProposalFile(t, filepath.Join(r.dir, ".git", "config"), []byte("[private-config-token\n"))
		}},
		{"different-signed-path", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			*path = "other.yaml"
			mustWriteProposalFile(t, filepath.Join(r.dir, *path), *reviewed)
			r.command(nil, "add", "--", *path)
			r.command(nil, "commit", "-m", "Fixture other path")
			*accepted = strings.TrimSpace(string(r.command(nil, "rev-parse", "HEAD")))
		}},
		{"path-escape", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			*path = "../application.yaml"
		}},
		{"metadata-path", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			*path = ".git/application.yaml"
		}},
		{"non-yaml-path", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			*path = "application.json"
		}},
		{"accepted-label", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			*accepted = "HEAD"
		}},
		{"restored-label", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			c.RestoredRevision = "HEAD~2"
		}},
		{"uppercase-previous", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			c.PreviousRevision = strings.Repeat("A", len(r.head))
		}},
		{"missing-previous", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			c.PreviousRevision = strings.Repeat("0", len(r.head))
		}},
		{"missing-restored", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			c.RestoredRevision = strings.Repeat("0", len(r.head))
		}},
		{"tag-object", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			r.command(nil, "tag", "-a", "previous", c.PreviousRevision, "-m", "Fixture tag")
			c.PreviousRevision = strings.TrimSpace(string(r.command(nil, "rev-parse", "previous")))
		}},
		{"tree-object", 11, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			c.PreviousRevision = strings.TrimSpace(string(r.command(nil, "rev-parse", c.PreviousRevision+"^{tree}")))
		}},
		{"empty-reviewed", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			*reviewed = nil
		}},
		{"binary-reviewed", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			*reviewed = []byte("private:\x00value\n")
		}},
		{"invalid-utf8-reviewed", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			*reviewed = []byte{0xff}
		}},
		{"oversized-reviewed", 2, func(t *testing.T, r proposalRepository, c *GitOpsSourceReversion, accepted, path *string, reviewed *[]byte) {
			*reviewed = bytes.Repeat([]byte{'x'}, maxGitOpsFileBytes+1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reviewed := []byte("kind: ConfigMap\ndata: {state: reviewed}\n")
			r, contract := newReversionRepository(t, reviewed, []byte("private: previous-source\n"))
			accepted, target := r.head, "application.yaml"
			tc.change(t, r, &contract, &accepted, &target, &reviewed)
			before := repositoryBytes(t, r.dir)
			facts, err := ObserveGitOpsReversion(context.Background(), &contract, accepted, target, reviewed)
			if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
				t.Fatal("rejected observation changed repository or .git bytes")
			}
			if spec.ExitCode(err) != tc.code || facts != (GitOpsReversionObservation{}) {
				t.Fatal("invalid evidence did not fail closed", facts, err)
			}
			if strings.Contains(err.Error(), "private:") || strings.Contains(err.Error(), "private-config-token") || strings.Contains(err.Error(), r.dir) {
				t.Fatal("rejection exposed source bytes or filesystem error details")
			}
		})
	}
}

func TestObserveGitOpsReversionRejectsHistoricalFileProfiles(t *testing.T) {
	for _, tc := range []struct {
		name  string
		code  int
		stage func(*testing.T, proposalRepository)
	}{
		{"binary", 2, func(t *testing.T, r proposalRepository) {
			mustWriteProposalFile(t, filepath.Join(r.dir, "application.yaml"), []byte("private:\x00previous\n"))
			r.command(nil, "add", "--", "application.yaml")
		}},
		{"invalid-utf8", 2, func(t *testing.T, r proposalRepository) {
			mustWriteProposalFile(t, filepath.Join(r.dir, "application.yaml"), []byte{0xff})
			r.command(nil, "add", "--", "application.yaml")
		}},
		{"oversized", 2, func(t *testing.T, r proposalRepository) {
			mustWriteProposalFile(t, filepath.Join(r.dir, "application.yaml"), bytes.Repeat([]byte{'x'}, maxGitOpsFileBytes+1))
			r.command(nil, "add", "--", "application.yaml")
		}},
		{"executable", 11, func(t *testing.T, r proposalRepository) {
			mustWriteProposalFile(t, filepath.Join(r.dir, "application.yaml"), []byte("private: executable-previous\n"))
			r.command(nil, "add", "--", "application.yaml")
			r.command(nil, "update-index", "--chmod=+x", "--", "application.yaml")
		}},
		{"symlink", 11, func(t *testing.T, r proposalRepository) {
			if err := os.Remove(filepath.Join(r.dir, "application.yaml")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("private-previous-target", filepath.Join(r.dir, "application.yaml")); err != nil {
				t.Fatal(err)
			}
			r.command(nil, "add", "--", "application.yaml")
		}},
		{"missing-file", 11, func(t *testing.T, r proposalRepository) {
			r.command(nil, "rm", "--", "application.yaml")
		}},
		{"attributes", 10, func(t *testing.T, r proposalRepository) {
			mustWriteProposalFile(t, filepath.Join(r.dir, "application.yaml"), []byte("private: attributed-previous\n"))
			mustWriteProposalFile(t, filepath.Join(r.dir, ".gitattributes"), []byte("*.yaml -text\n"))
			r.command(nil, "add", "--", "application.yaml", ".gitattributes")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reviewed := []byte("kind: ConfigMap\n")
			r := newProposalRepository(t, reviewed)
			restored := r.head
			tc.stage(t, r)
			r.command(nil, "commit", "-m", "Fixture unsupported historical file")
			previous := strings.TrimSpace(string(r.command(nil, "rev-parse", "HEAD")))
			r.command(nil, "reset", "--hard", restored)
			contract := &GitOpsSourceReversion{Repository: r.dir, PreviousRevision: previous, RestoredRevision: restored}
			before := repositoryBytes(t, r.dir)
			facts, err := ObserveGitOpsReversion(context.Background(), contract, restored, "application.yaml", reviewed)
			if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
				t.Fatal("historical-file rejection changed repository or .git bytes")
			}
			if spec.ExitCode(err) != tc.code || facts != (GitOpsReversionObservation{}) {
				t.Fatal("unsupported historical file admitted", facts, err)
			}
		})
	}
}

func TestObserveGitOpsReversionRejectsAbbreviatedSHA256Commits(t *testing.T) {
	for _, revision := range []string{"accepted", "restored", "previous"} {
		t.Run(revision, func(t *testing.T) {
			reviewed := []byte("kind: ConfigMap\n")
			r, contract := newReversionRepository(t, reviewed, []byte("kind: Secret\n"), "--object-format=sha256")
			accepted := r.head
			switch revision {
			case "accepted":
				accepted = accepted[:40]
			case "restored":
				contract.RestoredRevision = contract.RestoredRevision[:40]
			case "previous":
				contract.PreviousRevision = contract.PreviousRevision[:40]
			}
			before := repositoryBytes(t, r.dir)
			facts, err := ObserveGitOpsReversion(context.Background(), &contract, accepted, "application.yaml", reviewed)
			if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
				t.Fatal("abbreviated-commit rejection changed repository or .git bytes")
			}
			if spec.ExitCode(err) != 11 || facts != (GitOpsReversionObservation{}) {
				t.Fatal("abbreviated SHA-256 commit was treated as an exact commit", facts, err)
			}
		})
	}
}

func TestObserveGitOpsReversionOptionalContractAndCancellation(t *testing.T) {
	facts, err := ObserveGitOpsReversion(context.Background(), nil, "", "", nil)
	if err != nil || facts != (GitOpsReversionObservation{}) {
		t.Fatal("absent optional contract produced evidence or an error", facts, err)
	}
	reviewed := []byte("kind: ConfigMap\n")
	r, contract := newReversionRepository(t, reviewed, []byte("kind: Secret\n"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := repositoryBytes(t, r.dir)
	facts, err = ObserveGitOpsReversion(ctx, &contract, r.head, "application.yaml", reviewed)
	if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
		t.Fatal("canceled observation changed repository or .git bytes")
	}
	if err == nil || facts != (GitOpsReversionObservation{}) {
		t.Fatal("canceled observation produced evidence", facts, err)
	}
}

func TestObserveGitOpsReversionIsolatesHelpersAndDisablesLazyFetch(t *testing.T) {
	reviewed := []byte("kind: ConfigMap\ndata: {token: private-reviewed-token}\n")
	previous := []byte("kind: ConfigMap\ndata: {token: private-previous-token}\n")
	r, contract := newReversionRepository(t, reviewed, previous)
	helper := filepath.Join(t.TempDir(), "helper")
	sentinel := helper + ".executed"
	mustWriteProposalFile(t, helper, []byte("#!/bin/sh\nprintf invoked > \"$0.executed\"\nexit 1\n"))
	if err := os.Chmod(helper, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
			t.Error("Git executed a configured helper or attempted lazy fetching")
		}
	})
	for _, key := range []string{"core.fsmonitor", "core.hooksPath", "diff.external", "filter.custom.process", "core.sshCommand"} {
		r.command(nil, "config", key, helper)
	}
	r.command(nil, "config", "remote.origin.url", "ext::"+helper)
	r.command(nil, "config", "remote.origin.promisor", "true")
	r.command(nil, "config", "extensions.partialClone", "origin")
	r.command(nil, "config", "protocol.ext.allow", "always")
	t.Setenv("GIT_EXTERNAL_DIFF", helper)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
	t.Setenv("GIT_CONFIG_VALUE_0", helper)
	t.Setenv("GIT_OBJECT_DIRECTORY", "/private-config-token")
	t.Setenv("GIT_INDEX_FILE", "/private-config-token")
	before := repositoryBytes(t, r.dir)
	facts, err := ObserveGitOpsReversion(context.Background(), &contract, r.head, "application.yaml", reviewed)
	if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
		t.Fatal("helper-isolated observation changed repository or .git bytes")
	}
	if err != nil || facts.ManifestDigest != spec.Hash(reviewed) || facts.PreviousDigest != spec.Hash(previous) {
		t.Fatal("executable helpers or inherited configuration affected local evidence", facts, err)
	}
	encoded, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"private-reviewed-token", "private-previous-token", "private-config-token", r.dir, helper} {
		if bytes.Contains(encoded, []byte(raw)) {
			t.Fatal("observation output exposed raw file or configuration values")
		}
	}
	// A missing promised commit must fail locally, without invoking the remote helper.
	if err := os.Remove(filepath.Join(r.dir, ".git", "objects", contract.PreviousRevision[:2], contract.PreviousRevision[2:])); err != nil {
		t.Fatal(err)
	}
	before = repositoryBytes(t, r.dir)
	facts, err = ObserveGitOpsReversion(context.Background(), &contract, r.head, "application.yaml", reviewed)
	if !reflect.DeepEqual(before, repositoryBytes(t, r.dir)) {
		t.Fatal("missing-object rejection changed repository or .git bytes")
	}
	if spec.ExitCode(err) != 11 || facts != (GitOpsReversionObservation{}) {
		t.Fatal("missing promised commit did not fail closed", facts, err)
	}
	if strings.Contains(err.Error(), helper) || strings.Contains(err.Error(), r.dir) || strings.Contains(err.Error(), "fatal:") {
		t.Fatal("missing-object rejection exposed Git stderr or configuration values")
	}
}

func newReversionRepository(t *testing.T, reviewed, previous []byte, initOptions ...string) (proposalRepository, GitOpsSourceReversion) {
	t.Helper()
	r := newProposalRepository(t, reviewed, initOptions...)
	c := GitOpsSourceReversion{Repository: r.dir, RestoredRevision: r.head}
	c.PreviousRevision = commitReversionFile(t, r, previous)
	r.head = commitReversionFile(t, r, reviewed)
	return r, c
}

func commitReversionFile(t *testing.T, r proposalRepository, body []byte) string {
	t.Helper()
	mustWriteProposalFile(t, filepath.Join(r.dir, "application.yaml"), body)
	r.command(nil, "add", "--", "application.yaml")
	r.command(nil, "commit", "-m", "Fixture source change")
	return strings.TrimSpace(string(r.command(nil, "rev-parse", "HEAD")))
}
