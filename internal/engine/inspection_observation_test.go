package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ktesting "k8s.io/client-go/testing"
)

func inspectionFact(t *testing.T, snapshot spec.TargetSnapshot, name string) spec.Fact {
	t.Helper()
	for _, fact := range snapshot.Facts {
		if fact.Name == name {
			return fact
		}
	}
	t.Fatalf("missing target fact %s", name)
	return spec.Fact{}
}

func TestInspectionRetainsDeniedInventory(t *testing.T) {
	e, client, _ := fixture(t)
	client.PrependReactor("list", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "", errors.New("PRIVATE-DIAGNOSTIC"))
	})
	client.ClearActions()
	snapshot, err := e.Inspect(context.Background())
	if err != nil {
		t.Fatalf("denied inventory must remain a categorical partial observation: %v", err)
	}
	fact := inspectionFact(t, snapshot, "inventory/Deployment")
	if fact.Status != "denied" || fact.Value != "" {
		t.Fatalf("denial lost: %+v", fact)
	}
	blocked := false
	for _, finding := range snapshot.Findings {
		blocked = blocked || finding.Severity == "blocker"
	}
	if !blocked || snapshot.TargetID == "" || snapshot.NamespaceUID != "namespace-uid" {
		t.Fatalf("partial inventory lost its valid identity or blocker: %+v", snapshot)
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "PRIVATE-DIAGNOSTIC") {
		t.Fatal("server diagnostic leaked")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" && action.GetVerb() != "list" {
			t.Fatalf("inspection mutated target: %s", action.GetVerb())
		}
	}
}

func TestPlanKindsBlockIncompleteInventory(t *testing.T) {
	e, client, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	client.PrependReactor("list", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "", errors.New("private"))
	})
	snapshot, err := e.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"Plan", "ProbePlan", "RecoveryPlan", "RetirementPlan"} {
		t.Run(kind, func(t *testing.T) {
			plan := p
			plan.Kind, plan.Snapshot, plan.Executable = kind, snapshot, true
			e.addExecutionFindings(context.Background(), &plan, v, policy)
			if plan.Executable {
				t.Fatal("incomplete target inventory remained executable")
			}
			found := false
			for _, finding := range plan.Findings {
				found = found || finding.Code == "TARGET_OBSERVATION_INCOMPLETE" && finding.Severity == "blocker"
			}
			if !found {
				t.Fatalf("inventory blocker missing: %+v", plan.Findings)
			}
		})
	}
}

func TestInspectionDistinguishesFactFailures(t *testing.T) {
	for _, scope := range []struct {
		verb, resource, fact string
		required             bool
	}{
		{"get", "namespaces", "namespace.identity", true},
		{"list", "deployments", "inventory/Deployment", true},
		{"list", "secrets", "inventory/Secret", true},
		{"get", "secrets", "secret/token", false},
		{"list", "nodes", "nvidia.allocatable", false},
		{"get", "version", "kubernetes.version", false},
	} {
		for _, failure := range []struct {
			status string
			err    error
		}{
			{"absent", apierrors.NewNotFound(schema.GroupResource{Resource: scope.resource}, "missing")},
			{"denied", apierrors.NewForbidden(schema.GroupResource{Resource: scope.resource}, "", errors.New("PRIVATE"))},
			{"denied", apierrors.NewUnauthorized("PRIVATE")},
			{"stale", apierrors.NewResourceExpired("PRIVATE")},
			{"unavailable", errors.New("PRIVATE")},
		} {
			t.Run(scope.fact+"/"+failure.status+"/"+failure.err.Error(), func(t *testing.T) {
				e, client, _ := fixture(t)
				e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"token": {Name: "missing", Key: "token"}}
				client.PrependReactor(scope.verb, scope.resource, func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, failure.err })
				snapshot, err := e.Inspect(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				fact := inspectionFact(t, snapshot, scope.fact)
				if fact.Status != failure.status || fact.Value != "" {
					t.Fatalf("wrong fact: %+v", fact)
				}
				if scope.required && targetObservationError(snapshot) == nil {
					t.Fatal("required failed read did not block")
				}
				if scope.resource == "namespaces" {
					if snapshot.TargetID != "" || snapshot.NamespaceUID != "" {
						t.Fatal("failed namespace read manufactured an identity")
					}
					if inspectionFact(t, snapshot, "helm.release").Status != "unknown" {
						t.Fatal("skipped release read was presented as observed")
					}
				}
			})
		}
	}
	e, _, _ := fixture(t)
	snapshot, err := e.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fact := inspectionFact(t, snapshot, "inventory/StatefulSet"); fact.Status != "absent" || fact.Value != "0" {
		t.Fatalf("successful empty list not distinguished: %+v", fact)
	}
	if err := targetObservationError(snapshot); err != nil {
		t.Fatalf("successful empty inventory blocked: %v", err)
	}
}

func TestInspectionDistinguishesAbsentAndStaleHelmRelease(t *testing.T) {
	for _, status := range []string{"absent", "stale", "unavailable"} {
		t.Run(status, func(t *testing.T) {
			e, _, _ := fixture(t)
			e.HelmRunner = func(context.Context, ...string) ([]byte, error) {
				switch status {
				case "absent":
					return nil, errors.New("release: not found")
				case "stale":
					return []byte(`[{"revision":2,"status":"pending-upgrade"}]`), nil
				default:
					return nil, errors.New("PRIVATE")
				}
			}
			snapshot, err := e.Inspect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if fact := inspectionFact(t, snapshot, "helm.release"); fact.Status != status {
				t.Fatalf("wrong release fact: %+v", fact)
			}
			if (targetObservationError(snapshot) != nil) != (status != "absent") {
				t.Fatalf("wrong release gate: %+v", snapshot.Findings)
			}
		})
	}
}

func TestExecutionBoundariesRejectNewInventoryFailure(t *testing.T) {
	e, client, policy := fixture(t)
	p, v := fixturePlan(t, e, policy)
	client.PrependReactor("list", "services", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("PRIVATE") })
	ctx := context.Background()
	if err := e.checkPlan(ctx, p, v, policy, false); spec.ExitCode(err) != 10 {
		t.Fatalf("boundary accepted incomplete observation: %v", err)
	}
	if _, err := e.currentCheckpoint(ctx, "unused", p); spec.ExitCode(err) != 10 {
		t.Fatalf("checkpoint accepted incomplete observation: %v", err)
	}
	if _, err := e.advanceCheckpoint(ctx, "unused", p.Operations[0], p.Snapshot); spec.ExitCode(err) != 10 {
		t.Fatalf("checkpoint advanced with incomplete observation: %v", err)
	}
}
