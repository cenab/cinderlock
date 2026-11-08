package trustupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
)

func fixture(t *testing.T) (spec.TrustPolicy, spec.TrustPolicy, Body, ed25519.PrivateKey, time.Time) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	current := spec.TrustPolicy{Header: spec.NewHeader("TrustPolicy"), Spec: spec.TrustSpec{Epoch: 7, Keys: []spec.TrustedKey{{ID: "customer-policy", PublicKey: base64.StdEncoding.EncodeToString(public), Applications: []string{"*"}, Channels: []string{"*"}, Roles: []string{"policy"}}}, AllowedActions: []string{"helm", "job"}, MinSequence: map[string]int64{"app/stable": 5}}}
	current.Metadata.Name = "customer-root"
	candidate := current
	data, _ := spec.Canonical(current)
	if err := spec.Decode(data, &candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Spec.Epoch = 8
	when := time.Now().UTC().Truncate(time.Second)
	digest, err := spec.Digest(current)
	if err != nil {
		t.Fatal(err)
	}
	body := Body{Header: spec.NewHeader("TrustUpdate"), TargetID: "target-identity", PreviousPolicyDigest: digest, PreviousEpoch: 7, Candidate: candidate, IssuedAt: when.Format(time.RFC3339), ExpiresAt: when.Add(time.Hour).Format(time.RFC3339), DecisionReference: "change-123"}
	body.Metadata.Name = current.Metadata.Name
	return current, candidate, body, private, when
}

func TestAdmissionWritesNewPolicyAndCommitsExactTargetFloor(t *testing.T) {
	current, candidate, body, private, when := fixture(t)
	packet, err := Sign(body, "customer-policy", private)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := Verify(packet, current, body.TargetID, when)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	active := filepath.Join(dir, "active.json")
	output := filepath.Join(dir, "candidate.json")
	if err := spec.Write(active, current); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.ObservePolicyFloor(context.Background(), body.TargetID, current.Spec.Epoch, body.PreviousPolicyDigest); err != nil {
		t.Fatal(err)
	}
	receipt, err := Admit(context.Background(), packet, active, body.TargetID, preview.PacketDigest, output, store, when)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Admitted || receipt.CandidateDigest != preview.CandidateDigest || receipt.OutputPath != output {
		t.Fatalf("wrong admission receipt: %#v", receipt)
	}
	var written spec.TrustPolicy
	if err := spec.Read(output, &written); err != nil {
		t.Fatal(err)
	}
	writtenDigest, _ := spec.Digest(written)
	expectedDigest, _ := spec.Digest(candidate)
	if writtenDigest != expectedDigest {
		t.Fatal("admitted file differs from approved candidate")
	}
	unchanged, _ := os.ReadFile(active)
	if string(unchanged) != string(original) {
		t.Fatal("admission overwrote active trust policy")
	}
	if err := store.CheckPolicyFloor(context.Background(), body.TargetID, candidate.Spec.Epoch, expectedDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := Admit(context.Background(), packet, active, body.TargetID, preview.PacketDigest, filepath.Join(dir, "replay.json"), store, when); err == nil {
		t.Fatal("trust update replay admitted")
	}
}

func TestSignedUpdateUsesCurrentPolicyAuthorityAndExactNextEpoch(t *testing.T) {
	current, candidate, body, private, when := fixture(t)
	packet, err := Sign(body, "customer-policy", private)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := Verify(packet, current, body.TargetID, when)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := spec.Digest(candidate)
	if preview.CandidateDigest != digest || preview.PreviousEpoch != 7 || preview.Candidate.Spec.Epoch != 8 || preview.SignerKeyID != "customer-policy" || preview.DecisionReference != "change-123" {
		t.Fatalf("wrong authenticated preview: %#v", preview)
	}
}

func TestCandidateKeysAndVendorSignersCannotAuthorizePolicyUpdates(t *testing.T) {
	for _, scenario := range []string{"vendor-release-role", "candidate-self-trust", "revoked-admin", "application-scoped-admin", "release-key-alias", "formatted-release-key-alias"} {
		t.Run(scenario, func(t *testing.T) {
			current, _, body, private, when := fixture(t)
			keyID := "customer-policy"
			switch scenario {
			case "vendor-release-role":
				current.Spec.Keys[0].Roles = []string{"release"}
			case "candidate-self-trust":
				public, attacker, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				body.Candidate.Spec.Keys = append(body.Candidate.Spec.Keys, spec.TrustedKey{ID: "candidate-only", PublicKey: base64.StdEncoding.EncodeToString(public), Applications: []string{"*"}, Channels: []string{"*"}, Roles: []string{"policy"}})
				private = attacker
				keyID = "candidate-only"
			case "revoked-admin":
				current.Spec.Keys[0].Revoked = true
			case "application-scoped-admin":
				current.Spec.Keys[0].Applications = []string{"app"}
			case "release-key-alias", "formatted-release-key-alias":
				alias := current.Spec.Keys[0]
				alias.ID = "vendor-alias"
				alias.Roles = []string{"release"}
				if scenario == "formatted-release-key-alias" {
					alias.PublicKey = "\n" + alias.PublicKey + "\r\n"
				}
				current.Spec.Keys = append(current.Spec.Keys, alias)
			}
			body.PreviousPolicyDigest = mustDigest(t, current)
			packet, err := Sign(body, keyID, private)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(packet, current, body.TargetID, when); spec.ExitCode(err) != 16 {
				t.Fatalf("unadmitted policy authority accepted: %v", err)
			}
		})
	}
}

func mustDigest(t *testing.T, value any) string {
	t.Helper()
	digest, err := spec.Digest(value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestPolicyAdministratorRotationRequiresAnOverlapEpoch(t *testing.T) {
	current, _, body, firstPrivate, when := fixture(t)
	public, nextPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nextKey := spec.TrustedKey{ID: "next-policy", PublicKey: base64.StdEncoding.EncodeToString(public), Applications: []string{"*"}, Channels: []string{"*"}, Roles: []string{"policy"}}
	body.Candidate.Spec.Keys = []spec.TrustedKey{nextKey}
	packet, err := Sign(body, "customer-policy", firstPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(packet, current, body.TargetID, when); spec.ExitCode(err) != 16 {
		t.Fatalf("signer removed itself without overlap: %v", err)
	}
	body.Candidate.Spec.Keys = append([]spec.TrustedKey{current.Spec.Keys[0]}, nextKey)
	packet, err = Sign(body, "customer-policy", firstPrivate)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := Verify(packet, current, body.TargetID, when)
	if err != nil {
		t.Fatalf("valid overlap rejected: %v", err)
	}
	rotated := preview.Candidate
	rotated.Spec.Epoch++
	rotated.Spec.Keys = []spec.TrustedKey{nextKey}
	body.PreviousPolicyDigest = preview.CandidateDigest
	body.PreviousEpoch = preview.Candidate.Spec.Epoch
	body.Candidate = rotated
	body.DecisionReference = "remove-overlapped-key"
	packet, err = Sign(body, "next-policy", nextPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(packet, preview.Candidate, body.TargetID, when); err != nil {
		t.Fatalf("already admitted next administrator cannot complete rotation: %v", err)
	}
}

func TestAuthenticatedPacketsRejectStaleValidityAndChangedPolicyBinding(t *testing.T) {
	for _, scenario := range []string{"expired", "future", "wrong-previous-digest", "wrong-target", "revoked-candidate-signer", "key-id-reuse", "lowered-sequence-floor"} {
		t.Run(scenario, func(t *testing.T) {
			current, _, body, private, when := fixture(t)
			target := body.TargetID
			switch scenario {
			case "expired":
				body.IssuedAt = when.Add(-2 * time.Hour).Format(time.RFC3339)
				body.ExpiresAt = when.Add(-time.Hour).Format(time.RFC3339)
			case "future":
				body.IssuedAt = when.Add(time.Minute).Format(time.RFC3339)
			case "wrong-previous-digest":
				body.PreviousPolicyDigest = "sha256:" + strings.Repeat("a", 64)
			case "wrong-target":
				target = "another-target"
			case "revoked-candidate-signer":
				body.Candidate.Spec.Keys[0].Revoked = true
			case "key-id-reuse":
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				body.Candidate.Spec.Keys[0].PublicKey = base64.StdEncoding.EncodeToString(public)
			case "lowered-sequence-floor":
				body.Candidate.Spec.MinSequence["app/stable"] = 4
			}
			packet, err := Sign(body, "customer-policy", private)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(packet, current, target, when); spec.ExitCode(err) != 16 {
				t.Fatalf("invalid trust update admitted: %v", err)
			}
		})
	}
	_, _, body, private, _ := fixture(t)
	body.ExpiresAt = time.Now().Add(48 * time.Hour).Format(time.RFC3339)
	if _, err := Sign(body, "customer-policy", private); err == nil {
		t.Fatal("unbounded packet lifetime signed")
	}
}

func TestSignedBodyRequiresCanonicalStrictJSONAndIndependentDomain(t *testing.T) {
	current, _, body, private, when := fixture(t)
	packet, err := Sign(body, "customer-policy", private)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(packet.Body, &object); err != nil {
		t.Fatal(err)
	}
	object["unrecognizedAuthority"] = json.RawMessage("true")
	unknown, err := spec.Canonical(object)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{unknown, append([]byte(" "), packet.Body...), []byte(`{"targetID":"one","targetID":"two"}`)} {
		modified := packet
		modified.Body = data
		modified.Signature.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(Domain+"\x00"), data...)))
		if _, err := Verify(modified, current, body.TargetID, when); err == nil {
			t.Fatal("ambiguous or unknown signed fields accepted")
		}
	}
	packet.Domain = spec.BundleDomain
	if _, err := Verify(packet, current, body.TargetID, when); err == nil {
		t.Fatal("bundle domain accepted as trust update")
	}
	packet.Domain = Domain
	packet.Signature.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(spec.BundleDomain+"\x00"), packet.Body...)))
	if _, err := Verify(packet, current, body.TargetID, when); err == nil {
		t.Fatal("signature from another protocol domain accepted")
	}
}

func TestAdmissionRequiresExactReviewAndNewPolicyFile(t *testing.T) {
	for _, scenario := range []string{"wrong-reviewed-digest", "missing-baseline", "existing-output", "active-output", "symlink-input", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			current, _, body, private, when := fixture(t)
			packet, err := Sign(body, "customer-policy", private)
			if err != nil {
				t.Fatal(err)
			}
			preview, err := Verify(packet, current, body.TargetID, when)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			active := filepath.Join(dir, "active.json")
			output := filepath.Join(dir, "next.json")
			if err := spec.Write(active, current); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(active)
			if err != nil {
				t.Fatal(err)
			}
			store, err := state.Open(filepath.Join(dir, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if scenario != "missing-baseline" {
				if err := store.ObservePolicyFloor(context.Background(), body.TargetID, body.PreviousEpoch, body.PreviousPolicyDigest); err != nil {
					t.Fatal(err)
				}
			}
			approved := preview.PacketDigest
			ctx := context.Background()
			switch scenario {
			case "wrong-reviewed-digest":
				approved = "sha256:" + strings.Repeat("f", 64)
			case "existing-output":
				if err := os.WriteFile(output, []byte("keep this file"), 0600); err != nil {
					t.Fatal(err)
				}
			case "active-output":
				output = active
			case "symlink-input":
				link := filepath.Join(dir, "policy-link")
				if err := os.Symlink(active, link); err != nil {
					t.Fatal(err)
				}
				active = link
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if receipt, err := Admit(ctx, packet, active, body.TargetID, approved, output, store, when); err == nil || receipt.Admitted {
				t.Fatalf("unreviewed or destructive admission accepted: %#v %v", receipt, err)
			}
			unchanged, err := os.ReadFile(active)
			if err != nil || string(unchanged) != string(original) {
				t.Fatal("active policy modified by rejected admission")
			}
			if scenario == "existing-output" {
				data, _ := os.ReadFile(output)
				if string(data) != "keep this file" {
					t.Fatal("existing candidate path overwritten")
				}
			} else if scenario != "active-output" {
				if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("rejected admission published a policy")
				}
			}
			if scenario == "missing-baseline" {
				if _, err := store.PolicyFloor(context.Background(), body.TargetID); !errors.Is(err, state.ErrPolicyFloorMissing) {
					t.Fatal("admission silently enrolled a trust root")
				}
			} else if err := store.CheckPolicyFloor(context.Background(), body.TargetID, body.PreviousEpoch, body.PreviousPolicyDigest); err != nil {
				t.Fatal("rejected admission changed floor")
			}
		})
	}
}

func TestConcurrentApprovedUpdatesHaveOneDurableWinner(t *testing.T) {
	current, _, body, private, when := fixture(t)
	dir := t.TempDir()
	active := filepath.Join(dir, "active.json")
	if err := spec.Write(active, current); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.ObservePolicyFloor(context.Background(), body.TargetID, body.PreviousEpoch, body.PreviousPolicyDigest); err != nil {
		t.Fatal(err)
	}
	packets := []Packet{}
	previews := []Preview{}
	for _, decision := range []string{"change-one", "change-two"} {
		candidate := body
		candidate.DecisionReference = decision
		if decision == "change-two" {
			data, _ := spec.Canonical(candidate.Candidate)
			if err := spec.Decode(data, &candidate.Candidate); err != nil {
				t.Fatal(err)
			}
			candidate.Candidate.Spec.AllowedActions = []string{"job"}
		}
		packet, err := Sign(candidate, "customer-policy", private)
		if err != nil {
			t.Fatal(err)
		}
		preview, err := Verify(packet, current, body.TargetID, when)
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, packet)
		previews = append(previews, preview)
	}
	var wg sync.WaitGroup
	receipts := make([]Receipt, 2)
	failures := make([]error, 2)
	for index := range packets {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			receipts[index], failures[index] = Admit(context.Background(), packets[index], active, body.TargetID, previews[index].PacketDigest, filepath.Join(dir, []string{"one.json", "two.json"}[index]), store, when)
		}(index)
	}
	wg.Wait()
	winner := -1
	for index, receipt := range receipts {
		if failures[index] == nil && receipt.Admitted {
			if winner != -1 {
				t.Fatal("both competing policies admitted")
			}
			winner = index
		}
	}
	if winner == -1 {
		t.Fatalf("no approved update admitted: %v", failures)
	}
	if err := store.CheckPolicyFloor(context.Background(), body.TargetID, 8, previews[winner].CandidateDigest); err != nil {
		t.Fatal(err)
	}
	evidence, err := store.PolicyUpdateEvidence(context.Background(), body.TargetID, previews[winner].PacketDigest)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Receipt
	if err := spec.Decode(evidence, &persisted); err != nil {
		t.Fatal(err)
	}
	if !persisted.Admitted || persisted.PacketDigest != previews[winner].PacketDigest || persisted.SignerKeyID != "customer-policy" || persisted.DecisionReference != previews[winner].DecisionReference {
		t.Fatalf("admission audit does not identify winning decision: %#v", persisted)
	}
}

func TestPacketFilesPreserveAuthenticatedBodyAndRejectExtraEnvelopeFields(t *testing.T) {
	current, _, body, private, when := fixture(t)
	body.DecisionReference = "change <approved> $literal"
	packet, err := Sign(body, "customer-policy", private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "update.json")
	if err := Write(path, packet); err != nil {
		t.Fatal(err)
	}
	loaded, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Body) != string(packet.Body) {
		t.Fatal("packet writer changed authenticated body bytes")
	}
	if _, err := Verify(loaded, current, body.TargetID, when); err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	data, err := spec.Canonical(packet)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["candidateRootOverride"] = json.RawMessage("true")
	unknown, err := spec.Canonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unknown.json"), unknown, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(filepath.Join(dir, "unknown.json")); err == nil {
		t.Fatal("unknown packet envelope authority accepted")
	}
	pretty, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pretty.json"), pretty, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(filepath.Join(dir, "pretty.json")); err == nil {
		t.Fatal("noncanonical packet file accepted")
	}
}

func TestPreparedPolicyFileCannotBypassFailedFloorAdmission(t *testing.T) {
	current, _, body, private, when := fixture(t)
	packet, err := Sign(body, "customer-policy", private)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := Verify(packet, current, body.TargetID, when)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	active := filepath.Join(dir, "active.json")
	output := filepath.Join(dir, "prepared.json")
	database := filepath.Join(dir, "state.db")
	if err := spec.Write(active, current); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.ObservePolicyFloor(context.Background(), body.TargetID, body.PreviousEpoch, body.PreviousPolicyDigest); err != nil {
		t.Fatal(err)
	}
	faults, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer faults.Close()
	if _, err := faults.Exec(`CREATE TRIGGER reject_policy_update BEFORE INSERT ON policy_updates BEGIN SELECT RAISE(ABORT,'injected admission failure'); END`); err != nil {
		t.Fatal(err)
	}
	receipt, err := Admit(context.Background(), packet, active, body.TargetID, preview.PacketDigest, output, store, when)
	if spec.ExitCode(err) != 13 || !receipt.CandidatePrepared || receipt.Admitted || receipt.State != "needs_reconciliation" {
		t.Fatalf("failed floor commit misreported: %#v %v", receipt, err)
	}
	if err := store.CheckPolicyFloor(context.Background(), body.TargetID, body.PreviousEpoch, body.PreviousPolicyDigest); err != nil {
		t.Fatal("failed admission changed active floor")
	}
	if err := store.CheckPolicyFloor(context.Background(), body.TargetID, preview.Candidate.Spec.Epoch, preview.CandidateDigest); !errors.Is(err, state.ErrPolicyUnadmitted) {
		t.Fatalf("prepared file can bypass floor admission: %v", err)
	}
	var prepared spec.TrustPolicy
	if err := spec.Read(output, &prepared); err != nil || mustDigest(t, prepared) != preview.CandidateDigest {
		t.Fatalf("prepared candidate not recoverable for inspection: %v", err)
	}
	if _, err := faults.Exec(`DROP TRIGGER reject_policy_update`); err != nil {
		t.Fatal(err)
	}
	if repaired, err := Admit(context.Background(), packet, active, body.TargetID, preview.PacketDigest, filepath.Join(dir, "admitted.json"), store, when); err != nil || !repaired.Admitted {
		t.Fatalf("reviewed retry after fault failed: %#v %v", repaired, err)
	}
}
