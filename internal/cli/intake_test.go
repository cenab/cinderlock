package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/intake"
	"github.com/cenab/cinderlock/internal/spec"
)

func TestIntakeManifestFromVerifiedBundle(t *testing.T) {
	f := makeArtifactFixture(t)
	out := filepath.Join(f.h.dir, "intake.json")
	f.h.ok("bundle", "intake-manifest", f.bundlePath, "--trust", f.policyPath, "--out", out)
	body := string(read(t, out))
	if !strings.Contains(body, `"kind":"IntakeManifest"`) || !strings.Contains(body, `"application":"cli-fixture"`) {
		t.Fatal("intake manifest omitted the exact release identity", body)
	}
	if strings.Contains(body, f.h.dir) || strings.Contains(body, "tokenizer.json") || strings.Contains(body, "http://fixture") {
		t.Fatal("intake manifest leaked source paths or workflow endpoints")
	}
	if result := f.h.command("bundle", "intake-manifest", f.bundlePath, "--trust", f.policyPath, "--out", out); result.err == nil {
		t.Fatal("intake manifest overwritten")
	}
}

func TestIntakeCLIIndependentReceiptChainAndAnchoredReplayDenial(t *testing.T) {
	f := makeArtifactFixture(t)
	h := f.h
	manifestPath := filepath.Join(h.dir, "manifest.json")
	h.ok("bundle", "intake-manifest", f.bundlePath, "--trust", f.policyPath, "--out", manifestPath)
	private, public := filepath.Join(h.dir, "customer.key"), filepath.Join(h.dir, "customer.pub")
	h.ok("trust", "keygen", "--private", private, "--public", public)
	now := time.Now().UTC()
	policy := intake.CustodyPolicy{Header: spec.NewHeader("CustodyPolicy"), Keys: []intake.CustodyKey{{ID: "customer", PublicKey: string(read(t, public)), Custodians: []string{"receiving-team"}, Sites: []string{"offline-lab"}, Applications: []string{"cli-fixture"}, Profiles: []string{"artifact-unit-test"}, ExpiresAt: now.Add(48 * time.Hour).Format(time.RFC3339Nano)}}}
	keys := filepath.Join(h.dir, "custody.json")
	if err := spec.Write(keys, policy); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(h.dir, "receipt-1.json")
	signArgs := []string{"intake", "sign-receipt", "--manifest", manifestPath, "--bundle", f.bundlePath, "--trust", f.policyPath, "--keys", keys, "--previous-head", intake.Genesis, "--key", private, "--key-id", "customer", "--custodian", "receiving-team", "--site", "offline-lab", "--expires", now.Add(24 * time.Hour).Format(time.RFC3339Nano), "--out", receiptPath}
	h.ok(signArgs...)
	verifyArgs := []string{"intake", "verify-receipt", receiptPath, "--manifest", manifestPath, "--bundle", f.bundlePath, "--trust", f.policyPath, "--keys", keys, "--previous-head", intake.Genesis}
	unanchored := decode[intake.Verification](t, h.ok(verifyArgs...))
	if unanchored.Anchored || unanchored.PhysicalCustody != "not_observed" || unanchored.Approval != "not_attested" || unanchored.ExecutionAuthority != "none" {
		t.Fatal("receipt falsely established custody or execution authority", unanchored)
	}
	head := filepath.Join(h.dir, "custody-head.json")
	anchored := decode[intake.Verification](t, h.ok(append(verifyArgs, "--head-file", head)...))
	if !anchored.Anchored || anchored.ReceiptDigest != unanchored.ReceiptDigest {
		t.Fatal("wrong anchored receipt", anchored)
	}
	headBefore := string(read(t, head))
	if result := h.command(append(verifyArgs, "--head-file", head)...); spec.ExitCode(result.err) != 12 {
		t.Fatal("anchored replay accepted", result.err)
	}
	if string(read(t, head)) != headBefore {
		t.Fatal("denied replay changed the durable head")
	}
	before := string(read(t, receiptPath))
	if result := h.command(signArgs...); result.err == nil || string(read(t, receiptPath)) != before {
		t.Fatal("existing receipt overwritten")
	}
	policy.Keys[0].Revoked = true
	if err := os.WriteFile(keys, mustCanonical(t, policy), 0600); err != nil {
		t.Fatal(err)
	}
	if result := h.command(verifyArgs...); spec.ExitCode(result.err) != 12 {
		t.Fatal("current key revocation ignored", result.err)
	}
}

func mustCanonical(t *testing.T, v any) []byte {
	t.Helper()
	b, err := spec.Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIntakeDeadlineDoesNotPublishAManifest(t *testing.T) {
	f := makeArtifactFixture(t)
	out := filepath.Join(f.h.dir, "timed-out.json")
	result := f.h.command("bundle", "intake-manifest", f.bundlePath, "--trust", f.policyPath, "--out", out, "--timeout", "1ns")
	if spec.ExitCode(result.err) != 17 {
		t.Fatalf("intake deadline reported code %d: %v", spec.ExitCode(result.err), result.err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("incomplete verification published an intake manifest", err)
	}
}
