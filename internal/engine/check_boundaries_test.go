package engine

import (
	"context"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestFixtureVerifierWaitRechecksAuthorityBeforeAuthoredWorker(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "current-approval", true: "expired-approval"}[expire], func(t *testing.T) {
			e, client, p, v, _ := fixtureAcceptanceRun(t, "Plan")
			expired, authored := false, false
			client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
				job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
				command := job.Spec.Template.Spec.Containers[0].Command
				if len(command) > 2 && command[2] == "verify-model" {
					expired = true
				} else {
					authored = true
				}
				return false, nil, nil
			})
			guards := 0
			result := e.check(context.Background(), "fixture-run", p.Checks[0], v, func() (spec.TargetSnapshot, error) {
				guards++
				if expired && expire {
					return spec.TargetSnapshot{}, spec.Err(16, "approval expired during fixture verification")
				}
				return spec.TargetSnapshot{}, nil
			})
			want := "pass"
			if expire {
				want = "blocked"
			}
			if !expired || authored == expire || guards != 2 || result.Status != want {
				t.Fatalf("authored worker crossed fixture wait without current authority: expired=%v authored=%v guards=%d result=%#v", expired, authored, guards, result)
			}
			intent, err := e.Store.LatestOperation(context.Background(), "fixture-run", checkStepID(p.Checks[0].ID))
			wantState := "complete"
			if expire {
				wantState = "uncertain"
			}
			if err != nil || intent.State != wantState {
				t.Fatalf("interrupted check intent lost its conservative state: %v %#v", err, intent)
			}
			_, err = e.operationWorker(context.Background(), "fixture-run", intent.StepID, intent.Attempt, intent.StepID)
			if expire && err == nil {
				t.Fatal("unstarted authored worker gained durable identity")
			}
			if !expire && err != nil {
				t.Fatal("successful authored worker lost its original identity", err)
			}
		})
	}
}
