package support

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestAllowlistedExportAndImmutableApproval(t *testing.T) {
	r := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "run-1", TargetID: "private-target", SiteID: "private-site", State: "failed", Acceptance: "fail", Error: "SECRET-TOKEN", RecoveryCoverage: "secret topology", Findings: []spec.Finding{{Code: "CHECK_FAILED", Message: "SECRET-TOKEN", Evidence: "customer-document"}}, Checks: []spec.CheckResult{{ID: "inference", Required: true, Status: "fail", Reason: "customer-document", Evidence: "/private/path"}}}
	p, err := Collect(r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "export.json")
	if err = Export(p, p.Digest, path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-target", "private-site", "SECRET-TOKEN", "secret topology", "customer-document", "/private/path"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("export exposed", secret)
		}
	}
	p.Summary.State = "succeeded"
	other := filepath.Join(t.TempDir(), "changed.json")
	if err = Export(p, p.Digest, other); err == nil {
		t.Fatal("changed preview accepted")
	}
	if _, err = os.Stat(other); !os.IsNotExist(err) {
		t.Fatal("changed preview created output")
	}
	if err = Export(p, "wrong", path); err == nil {
		t.Fatal("wrong approval accepted")
	}
}
