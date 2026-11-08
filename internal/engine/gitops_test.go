package engine

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestGitOpsObservationUsesExactRevisionWithoutClaimingAcceptance(t *testing.T) {
	e, _, policy := fixture(t)
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "gitops-observe")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "gitops-observe")
	object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": map[string]any{"name": "application", "namespace": "gitops", "uid": "controller-uid", "generation": int64(4)}, "status": map[string]any{"observedGeneration": int64(4), "lastAppliedRevision": "main@sha1:exact", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}}
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), object)
	e.DynamicClient = client
	observed, err := e.ObserveGitOps(context.Background(), "flux", "gitops", "application", "main@sha1:exact", policy)
	if err != nil {
		t.Fatal(err)
	}
	if !observed.ControllerReady || observed.ApplicationAcceptance != "not_tested" {
		t.Fatalf("controller or acceptance status wrong: %#v", observed)
	}
	observed, err = e.ObserveGitOps(context.Background(), "flux", "gitops", "application", "main@sha1:different", policy)
	if err != nil {
		t.Fatal(err)
	}
	if observed.ControllerReady {
		t.Fatal("different desired source revision accepted")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" {
			t.Fatalf("GitOps observation mutated controller: %s", action.GetVerb())
		}
	}
}

func TestStaleFluxGenerationCannotBeReady(t *testing.T) {
	object := &unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"generation": int64(4)}, "status": map[string]any{"observedGeneration": int64(3), "lastAppliedRevision": "exact", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}}
	if observed := gitOpsStatus("flux", "exact", object); observed.ControllerReady {
		t.Fatal("stale generation treated as reconciled")
	}
}
