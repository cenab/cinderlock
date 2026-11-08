package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestObserveGitOpsProfileRejectsRepositorySourceOverrides(t *testing.T) {
	for _, name := range []string{".argocd-source.yaml", ".argocd-source-application.yaml"} {
		t.Run(name, func(t *testing.T) {
			f := newProfileFixture(t)
			mustWriteProposalFile(t, filepath.Join(f.repo.dir, name), []byte("directory:\n  include: '*.yaml'\n"))
			f.repo.command(nil, "add", "--", name)
			f.repo.command(nil, "commit", "-m", "Fixture source override")
			f.accepted(t, strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD"))))
			f.denied(t, "SOURCE_UNSUPPORTED")
		})
	}
}

func TestObserveGitOpsProfileLocalSourceDenials(t *testing.T) {
	for _, change := range []string{"dirty-work-file", "dirty-index", "clean-but-unreviewed", "wrong-head", "missing-target"} {
		t.Run(change, func(t *testing.T) {
			f := newProfileFixture(t)
			file := filepath.Join(f.repo.dir, "application.yaml")
			switch change {
			case "dirty-work-file":
				mustWriteProposalFile(t, file, []byte("unreviewed: true\n"))
			case "dirty-index":
				mustWriteProposalFile(t, file, []byte("unreviewed: true\n"))
				f.repo.command(nil, "add", "--", "application.yaml")
				mustWriteProposalFile(t, file, f.manifest)
			case "clean-but-unreviewed":
				mustWriteProposalFile(t, file, []byte("unreviewed: true\n"))
				f.repo.command(nil, "add", "--", "application.yaml")
				f.repo.command(nil, "commit", "-m", "Fixture unreviewed state")
				f.accepted(t, strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD"))))
			case "wrong-head":
				f.contract.AcceptedRevision = strings.Repeat("f", 40)
			case "missing-target":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			}
			f.seed(t)
			before := repositoryBytes(t, f.repo.dir)
			f.denied(t, "SOURCE_MISMATCH")
			if !reflect.DeepEqual(before, repositoryBytes(t, f.repo.dir)) {
				t.Fatal("denial modified source repository")
			}
		})
	}
}

func TestObserveGitOpsProfileHistoricalFileReversion(t *testing.T) {
	f := newProfileFixture(t)
	restored := f.repo.head
	file := filepath.Join(f.repo.dir, "application.yaml")
	mustWriteProposalFile(t, file, []byte("unreviewed: true\n"))
	f.repo.command(nil, "add", "--", "application.yaml")
	f.repo.command(nil, "commit", "-m", "Fixture previous file")
	previous := strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD")))
	mustWriteProposalFile(t, file, f.manifest)
	f.repo.command(nil, "add", "--", "application.yaml")
	f.repo.command(nil, "commit", "-m", "Fixture restored file")
	f.accepted(t, strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD"))))
	f.contract.Reversion = &spec.GitOpsProfileReversion{PreviousRevision: previous, RestoredRevision: restored}
	f.seed(t)
	before := repositoryBytes(t, f.repo.dir)
	o, err := f.observe()
	if err != nil || !o.Ready || o.Reversion == nil {
		t.Fatalf("same-repository file reversion rejected: %v %#v", err, o.Findings)
	}
	if o.Reversion.AcceptedRevision != f.repo.head || o.Reversion.PreviousRevision != previous || o.Reversion.RestoredRevision != restored || o.Reversion.Path != "application.yaml" || o.Reversion.ManifestDigest != spec.Hash(f.manifest) || o.ApplicationAcceptance != "not_established" {
		t.Fatalf("historical file bindings lost: %#v", o.Reversion)
	}
	f.assertReadOnly(t)
	f.assertWithheld(t, o, err)
	if !reflect.DeepEqual(before, repositoryBytes(t, f.repo.dir)) {
		t.Fatal("reversion observation modified source")
	}
	f.contract.Reversion.RestoredRevision = previous
	f.denied(t, "REVERSION_UNAVAILABLE")
	input, err := spec.Canonical(f.contract)
	if err != nil {
		t.Fatal(err)
	}
	input = bytes.Replace(input, []byte(`"previousRevision":`), []byte(`"repository":"/unrelated/repository","previousRevision":`), 1)
	var parsed spec.GitOpsProfileContract
	if spec.Decode(input, &parsed) == nil {
		t.Fatal("reversion accepted an independent repository")
	}
}
