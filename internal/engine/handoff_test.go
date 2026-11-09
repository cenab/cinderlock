package engine

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestRecoveryHandoffReconcilesJournalWriteInterruptions(t *testing.T) {
	for _, tc := range []struct{ name, boundary, corruption string }{
		{"successor-create", "successor-create", ""},
		{"successor-response-lost", "successor-response", ""},
		{"predecessor-update", "predecessor-update", ""},
		{"predecessor-response-lost", "predecessor-response", ""},
		{"missing-original-journal", "successor-create", "missing-source"},
		{"different-original-plan", "successor-create", "source-plan"},
		{"different-original-release", "successor-create", "source-release"},
		{"different-successor-edge", "predecessor-update", "source-edge"},
		{"conflicting-local-edge", "successor-create", "local-edge"},
		{"effects-without-successor-journal", "successor-create", "effects"},
		{"unrelated-unresolved-run", "successor-create", "other-run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			e, client, policy := fixture(t)
			original, v := fixturePlan(t, e, policy)
			storeResumePlan(t, e, original, v, "source-run")
			failed := newResult(original, "source-run", mustDigest(t, original))
			failed.State, failed.Error = "failed", "original synthetic failure"
			if err := e.Store.SetState(ctx, "source-run", "failed", true, failed); err != nil {
				t.Fatal(err)
			}
			p := original
			p.Kind, p.SourceRun = "RecoveryPlan", "source-run"
			p.Operations, p.Checks = p.Recovery[0].Operations, p.Recovery[0].Checks
			completeWorkers(client)
			interrupted := false
			client.PrependReactor("*", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
				if interrupted {
					return false, nil, nil
				}
				if (tc.boundary == "successor-create" || tc.boundary == "successor-response") && action.GetVerb() == "create" {
					cm := action.(ktesting.CreateAction).GetObject().(*corev1.ConfigMap)
					if cm.Data["runID"] != "source-run" {
						interrupted = true
						if tc.boundary == "successor-response" {
							if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, "test"); err != nil {
								t.Fatal(err)
							}
						}
						return true, nil, errors.New("synthetic journal interruption")
					}
				}
				if (tc.boundary == "predecessor-update" || tc.boundary == "predecessor-response") && action.GetVerb() == "update" {
					cm := action.(ktesting.UpdateAction).GetObject().(*corev1.ConfigMap)
					if cm.Data["runID"] == "source-run" {
						interrupted = true
						if tc.boundary == "predecessor-response" {
							if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, "test"); err != nil {
								t.Fatal(err)
							}
						}
						return true, nil, errors.New("synthetic journal interruption")
					}
				}
				return false, nil, nil
			})
			result, err := e.Apply(ctx, p, v, policy, nil, true)
			if !interrupted || err == nil || result.RunID == "" {
				t.Fatalf("missing interrupted handoff: %+v %v", result, err)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
					t.Fatal("worker preceded both journal writes")
				}
			}
			source, _ := e.Store.Run(ctx, "source-run")
			successor, _ := e.Store.Run(ctx, result.RunID)
			if source.Active || !successor.Active {
				t.Fatal("local gate was not atomically transferred")
			}
			if tc.corruption != "" {
				switch tc.corruption {
				case "missing-source":
					if err := client.CoreV1().ConfigMaps("test").Delete(ctx, "cinderlock-run-source-run", metav1.DeleteOptions{}); err != nil {
						t.Fatal(err)
					}
				case "source-plan", "source-release", "source-edge":
					cm, err := client.CoreV1().ConfigMaps("test").Get(ctx, "cinderlock-run-source-run", metav1.GetOptions{})
					if err != nil {
						t.Fatal(err)
					}
					switch tc.corruption {
					case "source-plan":
						cm.Data["planDigest"] = "wrong-plan"
					case "source-release":
						cm.Data["releaseName"] = "different-release"
					case "source-edge":
						cm.Data["state"], cm.Data["operation"] = "superseded", `{"recoveryRun":"different-successor"}`
					}
					if _, err := client.CoreV1().ConfigMaps("test").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
						t.Fatal(err)
					}
				case "local-edge":
					if err := e.Store.Event(ctx, "source-run", "run_superseded", map[string]string{"recoveryRun": "different-successor"}); err != nil {
						t.Fatal(err)
					}
				case "effects":
					if _, err := e.Store.Intent(ctx, result.RunID, p.Operations[0].ID, p.Operations[0], "uncertain-worker"); err != nil {
						t.Fatal(err)
					}
				case "other-run":
					if err := e.clusterRecord(ctx, "unrelated", mustDigest(t, original), "uncertain", nil); err != nil {
						t.Fatal(err)
					}
				}
				client.ClearActions()
			}
			resumed, err := e.Resume(ctx, result.RunID, v, policy, nil, true)
			if tc.corruption != "" {
				if err == nil {
					t.Fatal("corrupt or unproved handoff resumed")
				}
				current, _ := e.Store.Run(ctx, result.RunID)
				if !current.Active {
					t.Fatal("rejected handoff released the active gate")
				}
				for _, action := range client.Actions() {
					if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
						t.Fatal("rejected handoff started a worker")
					}
				}
				return
			}
			if err != nil || resumed.State != "recovered" || resumed.Acceptance != "pass" {
				t.Fatalf("recorded handoff did not resume: %+v %v", resumed, err)
			}
			after, _ := e.Store.Run(ctx, "source-run")
			if string(after.Result) != string(source.Result) || after.State != "failed" {
				t.Fatal("recovery rewrote original failure")
			}
			cm, err := client.CoreV1().ConfigMaps("test").Get(ctx, "cinderlock-run-source-run", metav1.GetOptions{})
			if err != nil || cm.Data["state"] != "superseded" {
				t.Fatalf("source cluster gate not transferred: %+v %v", cm, err)
			}
		})
	}
}

func TestRecoveryHandoffRequiresOriginalClusterJournalBeforeAdmission(t *testing.T) {
	ctx := context.Background()
	e, client, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	storeResumePlan(t, e, p, v, "source-run")
	if err := client.CoreV1().ConfigMaps("test").Delete(ctx, "cinderlock-run-source-run", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	p.Kind, p.SourceRun = "RecoveryPlan", "source-run"
	p.Operations, p.Checks = p.Recovery[0].Operations, p.Recovery[0].Checks
	client.ClearActions()
	if _, err := e.Apply(ctx, p, v, policy, nil, true); err == nil {
		t.Fatal("missing predecessor journal admitted a recovery")
	}
	source, _ := e.Store.Run(ctx, "source-run")
	if !source.Active {
		t.Fatal("missing predecessor journal released the original local gate")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" {
			t.Fatalf("missing source journal caused create %s", action.GetResource().Resource)
		}
	}
}

func TestRecoveryHandoffCannotSubstituteAnotherBundle(t *testing.T) {
	ctx := context.Background()
	e, client, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	storeResumePlan(t, e, p, v, "source-run")
	p.Kind, p.SourceRun = "RecoveryPlan", "source-run"
	p.Operations, p.Checks = p.Recovery[0].Operations, p.Recovery[0].Checks
	v.Digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	p.BundleDigest = v.Digest
	completeWorkers(client)
	if _, err := e.Apply(ctx, p, v, policy, nil, true); err == nil {
		t.Fatal("recovery substituted a different signed bundle for the original failed recipe")
	}
	source, _ := e.Store.Run(ctx, "source-run")
	if !source.Active {
		t.Fatal("different-bundle recovery transferred the original gate")
	}
}
