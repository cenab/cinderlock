package cli_test

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/catalog"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
)

func recordObservation(t *testing.T, h *harness, id, version string) {
	t.Helper()
	site := spec.Site{Header: spec.NewHeader("Site"), Spec: spec.SiteSpec{Profile: "cpu-test"}}
	site.Metadata.Name = "test-site"
	plan := spec.Plan{Header: spec.NewHeader("Plan"), Snapshot: spec.TargetSnapshot{TargetID: "test-target", SiteID: site.Metadata.Name}, BundleDigest: spec.Hash([]byte(version)), Checks: []spec.Check{{ID: "application", Domain: "workflow", Required: true, Type: "job", Image: "runner", Command: []string{"verify"}}}, RequiredChecks: []string{"application"}}
	plan.Checks[0].Script = checkScript("application")
	plan.Metadata = spec.Metadata{Application: "fixture", Version: version, Channel: "stable", Sequence: 1}
	plan.SiteDigest, _ = spec.Digest(site)
	run := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: id, SiteID: site.Metadata.Name, TargetID: plan.Snapshot.TargetID, BundleDigest: plan.BundleDigest, State: "succeeded", Acceptance: "pass", StartedAt: spec.Now(), FinishedAt: spec.Now(), Checks: []spec.CheckResult{{ID: "application", Domain: "workflow", Required: true, Status: "pass"}}, Domains: map[string]string{"workflow": "pass"}}
	run.Metadata = plan.Metadata
	run.PlanDigest, _ = spec.Digest(plan)
	planBytes, _ := spec.Canonical(plan)
	siteBytes, _ := spec.Canonical(site)
	store, err := state.Open(filepath.Join(h.state, "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.CreateRun(context.Background(), state.Run{ID: id, Application: "fixture", Namespace: "test", TargetID: run.TargetID, State: "verifying", PlanDigest: run.PlanDigest, BundleDigest: run.BundleDigest, Plan: planBytes, Site: siteBytes}); err != nil {
		t.Fatal(err)
	}
	if err = store.SetState(context.Background(), id, "succeeded", false, run); err != nil {
		t.Fatal(err)
	}
}

func TestLocalComparisonAndExternalEvidenceCLI(t *testing.T) {
	h := newHarness(t)
	recordObservation(t, h, "before", "1.0.0")
	recordObservation(t, h, "after", "2.0.0")
	comparison := decode[catalog.RunComparison](t, h.ok("run", "compare", "before", "after"))
	if !comparison.Comparable || comparison.After.Version != "2.0.0" || comparison.After.Acceptance != "pass" {
		t.Fatal(comparison)
	}
	subject := decode[catalog.EvidenceSubject](t, h.ok("evidence", "subject", "after"))
	keyPath, pubPath := filepath.Join(h.dir, "evidence.key"), filepath.Join(h.dir, "evidence.pub")
	h.ok("trust", "keygen", "--private", keyPath, "--public", pubPath)
	key, err := bundle.ParsePublicKey(string(read(t, pubPath)))
	if err != nil {
		t.Fatal(err)
	}
	keys := []catalog.EvidenceKey{{ID: "scanner", PublicKey: base64.StdEncoding.EncodeToString(key), Producer: "scanner", Versions: []string{"1.0.0"}, Projects: []string{"project"}, Sites: []string{"test-site"}, Applications: []string{"fixture"}, Profiles: []string{"cpu-test"}, Scopes: []string{"security-scan"}}}
	keysPath := filepath.Join(h.dir, "evidence-keys.json")
	if err = spec.Write(keysPath, keys); err != nil {
		t.Fatal(err)
	}
	body := catalog.ExternalEvidence{Project: "project", Site: "test-site", Producer: catalog.EvidenceProducer{Name: "scanner", Version: "1.0.0"}, Subject: subject, ObservedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), Scope: "security-scan", ClaimedResult: "pass", Checks: []catalog.EvidenceCheck{{ID: "package-scan", Status: "pass"}}, Coverage: []string{"synthetic CLI signature fixture"}, Limitations: []string{"no scanner was executed"}}
	bodyPath, packetPath := filepath.Join(h.dir, "body.json"), filepath.Join(h.dir, "evidence.json")
	if err = spec.Write(bodyPath, body); err != nil {
		t.Fatal(err)
	}
	h.ok("evidence", "sign", bodyPath, "--key", keyPath, "--key-id", "scanner", "--out", packetPath)
	verified := decode[catalog.VerifiedExternalEvidence](t, h.ok("evidence", "verify", packetPath, "--keys", keysPath, "--run", "after", "--project", "project", "--scope", "security-scan"))
	if verified.Integrity != "verified" || verified.Acceptance != "attached_evidence_only" {
		t.Fatal(verified)
	}
	if r := h.command("evidence", "verify", packetPath, "--keys", keysPath, "--run", "before", "--project", "project", "--scope", "security-scan"); r.err == nil {
		t.Fatal("evidence rebound to another run")
	}
}
