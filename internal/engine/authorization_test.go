package engine

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestAuthorizationRequiresSeparateApprovalRoleAndExactPlan(t *testing.T) {
	e, _, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy.Spec.Keys = []spec.TrustedKey{{ID: "customer", PublicKey: base64.StdEncoding.EncodeToString(public), Applications: []string{"app"}, Channels: []string{"stable"}, Roles: []string{"release"}}}
	p.PolicyDigest, _ = spec.Digest(policy)
	digest, _ := spec.Digest(p)
	a := spec.Authorization{Header: spec.NewHeader("Authorization"), PlanDigest: digest, PlanKind: "Plan", TargetID: p.Snapshot.TargetID, PolicyDigest: p.PolicyDigest, PolicyEpoch: 1, Actions: []string{"migrate", "job"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Nonce: "unique"}
	if err := spec.SignAuthorization(&a, private, "customer"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.authorize(p, policy, &a, false); spec.ExitCode(err) != 16 {
		t.Fatalf("release key was accepted as customer approval: %v", err)
	}
	policy.Spec.Keys[0].Roles = []string{"approval"}
	p.PolicyDigest, _ = spec.Digest(policy)
	a.PolicyDigest = p.PolicyDigest
	a.PlanDigest, _ = spec.Digest(p)
	_ = spec.SignAuthorization(&a, private, "customer")
	if _, err := e.authorize(p, policy, &a, false); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name string
		edit func(*spec.WorkerResources, *int64)
	}{
		{"cpu", func(r *spec.WorkerResources, _ *int64) { r.CPUMillis++ }},
		{"memory", func(r *spec.WorkerResources, _ *int64) { r.MemoryBytes++ }},
		{"ephemeral", func(r *spec.WorkerResources, _ *int64) { r.EphemeralStorageBytes++ }},
		{"temporary", func(r *spec.WorkerResources, _ *int64) { r.TemporaryBytes++ }},
		{"timeout", func(_ *spec.WorkerResources, seconds *int64) { (*seconds)++ }},
	} {
		for _, owner := range []string{"operation", "check"} {
			t.Run(owner+"/"+change.name, func(t *testing.T) {
				body, err := spec.Canonical(p)
				if err != nil {
					t.Fatal(err)
				}
				var changed spec.Plan
				if err := spec.Decode(body, &changed); err != nil {
					t.Fatal(err)
				}
				if owner == "operation" {
					change.edit(changed.Operations[0].Script.Resources, &changed.Operations[0].TimeoutSeconds)
				} else {
					change.edit(changed.Checks[0].Script.Resources, &changed.Checks[0].TimeoutSeconds)
				}
				if _, err := e.authorize(changed, policy, &a, false); spec.ExitCode(err) != 16 {
					t.Fatalf("changed allocation reused exact-plan approval: %v", err)
				}
				if err := e.verifyRecipeBinding(changed, v); spec.ExitCode(err) != 12 {
					t.Fatalf("changed allocation matched signed release: %v", err)
				}
			})
		}
	}
	a.TargetID = "another-target"
	_ = spec.SignAuthorization(&a, private, "customer")
	if _, err := e.authorize(p, policy, &a, false); spec.ExitCode(err) != 16 {
		t.Fatalf("wrong target authorization accepted: %v", err)
	}
}

func TestAuthorizationRequiresCheckAndPhaseCapabilities(t *testing.T) {
	e, _, policy := fixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy.Spec.Keys = []spec.TrustedKey{{ID: "customer", PublicKey: base64.StdEncoding.EncodeToString(public), Applications: []string{"app"}, Channels: []string{"stable"}, Roles: []string{"approval"}}}
	for _, test := range []struct {
		kind    string
		checks  []spec.Check
		actions []string
	}{
		{"Plan", []spec.Check{{Type: "job"}}, []string{"helm", "job"}},
		{"ArtifactsPlan", nil, []string{"helm", "gitops-stage"}},
		{"GitOpsPreparePlan", nil, []string{"helm", "gitops-prepare"}},
		{"GitOpsChecksPlan", []spec.Check{{Type: "job"}}, []string{"helm", "job", "gitops-check", "gitops-observe"}},
	} {
		t.Run(test.kind, func(t *testing.T) {
			p := spec.Plan{Header: spec.NewHeader(test.kind), PolicyDigest: mustDigest(t, policy), PolicyEpoch: policy.Spec.Epoch, Operations: []spec.Operation{{Type: "helm"}}, Checks: test.checks, Snapshot: spec.TargetSnapshot{TargetID: "target"}}
			p.Metadata = spec.Metadata{Application: "app", Channel: "stable"}
			a := spec.Authorization{Header: spec.NewHeader("Authorization"), PlanDigest: mustDigest(t, p), PlanKind: p.Kind, TargetID: p.Snapshot.TargetID, PolicyDigest: p.PolicyDigest, PolicyEpoch: p.PolicyEpoch, Actions: test.actions, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Nonce: "capability-approval"}
			if err := spec.SignAuthorization(&a, private, "customer"); err != nil {
				t.Fatal(err)
			}
			if nonce, err := e.authorize(p, policy, &a, false); err != nil || nonce != a.Nonce {
				t.Fatalf("complete authorization rejected: nonce=%q error=%v", nonce, err)
			}
			for i, action := range test.actions {
				missing := a
				missing.Actions = append(append([]string{}, test.actions[:i]...), test.actions[i+1:]...)
				if err := spec.SignAuthorization(&missing, private, "customer"); err != nil {
					t.Fatal(err)
				}
				if _, err := e.authorize(p, policy, &missing, false); spec.ExitCode(err) != 16 || !strings.Contains(err.Error(), action) {
					t.Fatalf("signed authorization omitted %s: %v", action, err)
				}
			}
		})
	}
}
