package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestGitOpsValidationCancellationIsNotAConflictingInventory(t *testing.T) {
	f := newGitOpsExecutionFixture(t, gitOpsFixtureOptions{data: true})
	p, err := f.e.GitOpsDataChecksPlan(context.Background(), f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interrupted := false
	f.kube.PrependReactor("list", "jobs", func(ktesting.Action) (bool, runtime.Object, error) {
		interrupted = true
		cancel()
		return true, nil, context.Canceled
	})
	f.kube.ClearActions()
	err = f.e.ValidatePlan(ctx, p, f.v, f.policy)
	if !interrupted || spec.ExitCode(err) != 13 || !strings.Contains(err.Error(), "canceled") {
		t.Fatal("canceled observation became conflicting inventory", interrupted, err)
	}
	for _, action := range f.kube.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
			t.Fatal("validation created a worker after interruption")
		}
	}
}

func TestGitOpsFixtureReadDeadlineRemainsUnverified(t *testing.T) {
	ctx := context.Background()
	f := newGitOpsExecutionFixture(t, gitOpsFixtureOptions{models: true, data: true})
	p, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	run, err := f.e.Apply(ctx, p, f.v, f.policy, f.approval(t, p), false)
	if err != nil || run.Acceptance != "pass" {
		t.Fatal("fixture control did not complete", err)
	}
	var seed spec.Operation
	for _, check := range p.Checks {
		if len(check.Fixtures) > 0 {
			seeds, err := fixtureSeeds(p, check)
			if err != nil || len(seeds) == 0 {
				t.Fatal(err)
			}
			seed = seeds[0]
			break
		}
	}
	if seed.ID == "" {
		t.Fatal("control has no native acceptance fixture")
	}
	worker, err := f.e.Store.Worker(ctx, run.RunID, seed.ID, 1, seed.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.kube.PrependReactor("get", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		if action.(ktesting.GetAction).GetName() == worker.Name {
			return true, nil, errors.New("client rate limiter Wait would exceed context deadline")
		}
		return false, nil, nil
	})
	err = f.e.gitOpsUnreferencedClaim(ctx, run.RunID, seed.PVC)
	if spec.ExitCode(err) != 13 || !strings.Contains(err.Error(), "rate limiter") || ctx.Err() != nil {
		t.Fatal("unavailable read became changed Job evidence", err)
	}
	if err := f.e.checkExecutionProfile(ctx, p, f.v, f.policy); spec.ExitCode(err) != 13 {
		t.Fatal("unverified fixture became an unsupported recipe", err)
	}
}
