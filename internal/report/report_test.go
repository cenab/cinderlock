package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestReportEscapesLocalEvidenceAndRetainsGaps(t *testing.T) {
	r := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "run-1", State: "needs_reconciliation", Acceptance: "blocked", Error: "<script>alert(1)</script>", Domains: map[string]string{"integrity": "pass", "workflow": "blocked"}, Checks: []spec.CheckResult{{ID: "login", Required: true, Status: "blocked", Reason: "no approved browser path"}}}
	var b bytes.Buffer
	if err := Render(&b, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Skip to results", "not tested", "no approved browser path", "Do not repeat an uncertain migration", "scope=\"col\"", "&lt;script&gt;"} {
		if !strings.Contains(b.String(), want) {
			t.Fatal("missing report content", want)
		}
	}
	if strings.Contains(b.String(), "<script>alert(1)</script>") || strings.Contains(b.String(), "https://") {
		t.Fatal("active or remote HTML content present")
	}
	b.Reset()
	if err := Markdown(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "workflow | blocked") {
		t.Fatal(b.String())
	}
}
