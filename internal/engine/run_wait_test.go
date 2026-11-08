package engine

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
)

func TestLocalWaitCancellationRetainsCompletedChecksAndOriginalWorkers(t *testing.T) {
	e, client, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	optional := p.Checks[0]
	optional.ID, optional.Required, optional.Script = "optional-negative", false, fixtureScript("optional-negative")
	p.Checks = append(p.Checks, optional)
	v.Index.Lock.Release.Spec.Checks = p.Checks
	chart := chartFixture(t, e)
	v.Root = chart.Root
	v.Index.Lock.Assets = append(v.Index.Lock.Assets, chart.Index.Lock.Assets...)
	nativeHelm := e.HelmRunner
	e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "template" {
			return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: app}\ndata: {mode: test}\n"), nil
		}
		return nativeHelm(ctx, args...)
	}
	var err error
	p, err = e.Plan(context.Background(), v, p.BundlePath, p.SitePath, policy)
	if err != nil || !p.Executable {
		t.Fatalf("test release is not executable: %v %#v", err, p.Findings)
	}
	client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		job.UID = types.UID("uid-" + job.Name)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		return false, nil, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelled := false
	client.PrependReactor("get", "leases", func(action ktesting.Action) (bool, runtime.Object, error) {
		if !cancelled {
			for _, check := range p.Checks[:1] {
				runs, err := e.Store.Runs(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				for _, run := range runs {
					attempt, err := e.Store.LatestOperation(context.Background(), run.ID, checkStepID(check.ID))
					if err == nil && attempt.State == "complete" {
						cancelled = true
						cancel()
					}
				}
			}
		}
		return false, nil, nil
	})
	result, err := e.Apply(ctx, p, v, policy, nil, true)
	if !cancelled {
		t.Fatalf("test did not end the local wait after its durable required check: %v %#v", err, result)
	}
	if spec.ExitCode(err) != 13 || result.State != "needs_reconciliation" || !strings.Contains(result.Error, "local execution wait") {
		t.Fatalf("cancelled observation became a false target/fixture outcome: code=%d error=%v result=%#v", spec.ExitCode(err), err, result)
	}
	if result.Acceptance != "not_established" || len(result.Checks) != 1 || result.Checks[0].ID != p.Checks[0].ID || result.Checks[0].Status != "pass" {
		t.Fatalf("completed check evidence was lost or acceptance fabricated: %#v", result)
	}
	record, err := e.Store.Run(context.Background(), result.RunID)
	if err != nil || !record.Active || record.State != "needs_reconciliation" {
		t.Fatal("local wait released unresolved run", record, err)
	}
	if _, err = e.Store.LatestOperation(context.Background(), result.RunID, checkStepID(optional.ID)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("unstarted optional check gained an intent", err)
	}
	workers, err := e.Store.Workers(context.Background(), result.RunID)
	if err != nil || len(workers) != 2 {
		t.Fatal("original workers were duplicated or lost", workers, err)
	}
	floor, err := e.Store.ReleaseFloor(context.Background(), result.TargetID, p.Metadata.Application, p.Metadata.Channel)
	if err != nil || floor != 0 {
		t.Fatal("cancelled run advanced release acceptance", floor, err)
	}
}
