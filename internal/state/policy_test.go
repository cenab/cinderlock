package state

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyFloorRequiresApprovedAdvanceAndNeverRollsBack(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first := "sha256:" + strings.Repeat("a", 64)
	next := "sha256:" + strings.Repeat("b", 64)
	conflict := "sha256:" + strings.Repeat("c", 64)
	if err := store.ObservePolicyFloor(ctx, "target", 3, first); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckPolicyFloor(ctx, "target", 3, first); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckPolicyFloor(ctx, "target", 2, first); !errors.Is(err, ErrPolicyRollback) {
		t.Fatalf("policy rollback admitted: %v", err)
	}
	if err := store.CheckPolicyFloor(ctx, "target", 3, conflict); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("same epoch different policy admitted: %v", err)
	}
	if err := store.CheckPolicyFloor(ctx, "target", 4, next); !errors.Is(err, ErrPolicyUnadmitted) {
		t.Fatalf("unadmitted ahead policy accepted: %v", err)
	}
	if err := store.AdvancePolicyFloor(ctx, "target", 3, first, 4, next, conflict); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckPolicyFloor(ctx, "target", 4, next); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvancePolicyFloor(ctx, "target", 3, first, 4, conflict, next); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("stale policy update overwrote admitted candidate: %v", err)
	}
	if err := store.ObservePolicyFloor(ctx, "target", 3, first); !errors.Is(err, ErrPolicyRollback) {
		t.Fatalf("observed rollback replaced floor: %v", err)
	}
	floor, err := store.PolicyFloor(ctx, "target")
	if err != nil || floor.Epoch != 4 || floor.Digest != next || floor.UpdateDigest != conflict {
		t.Fatalf("wrong policy floor persisted: %#v %v", floor, err)
	}
	if err := store.ObservePolicyFloor(ctx, "other-target", 1, conflict); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyFloorAndAdmissionReceiptCommitTogether(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first := "sha256:" + strings.Repeat("a", 64)
	next := "sha256:" + strings.Repeat("b", 64)
	packet := "sha256:" + strings.Repeat("c", 64)
	if err := store.ObservePolicyFloor(ctx, "target", 3, first); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_policy_receipt BEFORE INSERT ON policy_update_evidence BEGIN SELECT RAISE(ABORT,'receipt write failed'); END`); err != nil {
		t.Fatal(err)
	}
	evidence := json.RawMessage(`{"signerKeyID":"customer-policy","decisionReference":"change-123"}`)
	if err := store.AdvancePolicyFloor(ctx, "target", 3, first, 4, next, packet, evidence); err == nil {
		t.Fatal("policy floor advanced without required receipt")
	}
	if err := store.CheckPolicyFloor(ctx, "target", 3, first); err != nil {
		t.Fatal("receipt failure did not roll back policy floor")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_policy_receipt`); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvancePolicyFloor(ctx, "target", 3, first, 4, next, packet, evidence); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.PolicyUpdateEvidence(ctx, "target", packet)
	if err != nil || string(persisted) != string(evidence) {
		t.Fatalf("policy receipt not durable: %s %v", persisted, err)
	}
}
