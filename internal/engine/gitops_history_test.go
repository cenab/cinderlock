package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestAcceptedGitOpsInventoryIsHistoricalUnderCurrentPolicy(t *testing.T) {
	for _, change := range []string{"none", "result-digest", "source-path", "resource-uid", "failed-run"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			f := newGitOpsExecutionFixture(t, gitOpsFixtureOptions{})
			plan, err := f.e.GitOpsChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
			if err != nil || !plan.Executable {
				t.Fatal("control check plan", err, plan.Findings)
			}
			result, err := f.e.Apply(ctx, plan, f.v, f.policy, f.approval(t, plan), false)
			if err != nil || result.Acceptance != "pass" {
				t.Fatal("control acceptance", err, result)
			}
			ref := spec.GitOpsRunReference{RunID: result.RunID, PlanDigest: result.PlanDigest, ResultDigest: mustDigest(t, result)}
			next := *f.v
			if err := spec.Decode(mustCanonical(t, f.v.Index), &next.Index); err != nil {
				t.Fatal(err)
			}
			next.Digest = spec.Hash([]byte("different future signed bundle"))
			oldRenderer := f.e.HelmRunner
			f.e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
				body, err := oldRenderer(ctx, args...)
				if args[0] == "template" {
					objects, parseErr := PermissionObjects(body)
					if parseErr != nil {
						return nil, parseErr
					}
					for _, object := range objects {
						if object["kind"] == "ConfigMap" {
							object["data"] = map[string]any{"setting": "future-config"}
						}
					}
					return encodeObjects(objects)
				}
				return body, err
			}
			if _, err := f.e.RenderDesiredState(ctx, &next); err != nil {
				t.Fatal("future control render", err)
			}
			if observation, err := f.e.ObserveGitOpsProfile(ctx, &next, f.policy, f.sitePath, f.contract, f.manifest); spec.ExitCode(err) != 2 {
				t.Fatalf("new bundle did not reach exact render comparison: %v %+v", err, observation.Findings)
			}
			f.e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
				if args[0] == "template" {
					t.Fatal("historical inventory rendered the future application")
				}
				return oldRenderer(ctx, args...)
			}
			// The completed acceptance does not need its old approval key to stay current.
			public, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			f.policy.Spec.Epoch++
			f.policy.Spec.Keys[0].ID = "rotated-customer"
			f.policy.Spec.Keys[0].PublicKey = base64.StdEncoding.EncodeToString(public)
			if err := os.WriteFile(f.e.Site.Spec.TrustPolicy, mustCanonical(t, f.policy), 0600); err != nil {
				t.Fatal(err)
			}
			if err := f.e.Store.ObservePolicyFloor(ctx, plan.Snapshot.TargetID, f.policy.Spec.Epoch, mustDigest(t, f.policy)); err != nil {
				t.Fatal(err)
			}
			sourcePath := "application.yaml"
			switch change {
			case "result-digest":
				ref.ResultDigest = spec.Hash([]byte("different-result"))
			case "source-path":
				sourcePath = "different.yaml"
			case "resource-uid":
				f.live[0].SetUID("replacement-deployment")
				f.seed(t)
			case "failed-run":
				result.State, result.Acceptance = "failed", "not_established"
				if err := f.e.Store.SetState(ctx, result.RunID, "failed", false, result); err != nil {
					t.Fatal(err)
				}
			}
			f.kube.ClearActions()
			f.client.ClearActions()
			observation, bound, previous, err := f.e.observeAcceptedGitOps(ctx, ref, f.policy, f.sitePath, f.contract, sourcePath, f.manifest)
			if change != "none" {
				if err == nil {
					t.Fatal("changed accepted evidence passed", change)
				}
			} else if err != nil || !observation.Ready || bound != ref || previous.BundleDigest != plan.BundleDigest || observation.BundleDigest != plan.BundleDigest || observation.PolicyDigest != mustDigest(t, f.policy) {
				t.Fatalf("current authority could not observe exact historical inventory: %v %+v", err, observation)
			}
			f.assertReadOnly(t)
		})
	}
}
