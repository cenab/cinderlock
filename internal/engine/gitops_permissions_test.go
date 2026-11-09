package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	authorizationv1 "k8s.io/api/authorization/v1"
)

func TestGitOpsChecksDisclosePreparedClaimReadsWithoutResourceWritePermission(t *testing.T) {
	e, requests := permissionServer(t, func(authorizationv1.ResourceAttributes) authorizationv1.SubjectAccessReviewStatus {
		return authorizationv1.SubjectAccessReviewStatus{Allowed: true}
	})
	p := spec.Plan{Header: spec.NewHeader("GitOpsChecksPlan"), GitOps: &spec.GitOpsPlanBinding{Preparation: &spec.GitOpsRunReference{RunID: "prepared"}, Contract: &spec.GitOpsProfileContract{Namespace: "argocd", Name: "application"}}, Snapshot: spec.TargetSnapshot{Facts: []spec.Fact{{Name: "gitops/prepared-volume/model-v2", Status: "known"}}}, Checks: []spec.Check{{ID: "workflow", Type: "job"}}}
	objects := []map[string]any{{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "application"}, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccountName": "application", "automountServiceAccountToken": false}}}}}
	findings := e.PermissionFindings(context.Background(), p, objects)
	disclosed := false
	for _, finding := range findings {
		if finding.Code == "SERVICE_ACCOUNT_REQUIRED" && finding.Source == "controller-observation" && finding.Severity == "info" && strings.Contains(finding.Message, "tenant-a/application") && strings.Contains(finding.Message, "automountServiceAccountToken=false") && strings.Contains(finding.Message, "grants are unverified") {
			disclosed = true
		}
	}
	if !disclosed {
		t.Fatal("controller-owned workload identity was not disclosed as advisory", findings)
	}
	wanted := map[string]bool{"model-claim": false, "receiver-pod": false, "pending-job": false, "controller": false}
	for _, attributes := range requests() {
		switch {
		case attributes.Resource == "persistentvolumeclaims" && attributes.Name == "model-v2" && attributes.Verb == "get":
			wanted["model-claim"] = true
		case attributes.Resource == "pods" && attributes.Verb == "get":
			wanted["receiver-pod"] = true
		case attributes.Resource == "jobs" && attributes.Verb == "list":
			wanted["pending-job"] = true
		case attributes.Resource == "applications" && attributes.Namespace == "argocd" && attributes.Name == "application" && attributes.Verb == "get":
			wanted["controller"] = true
		}
		if attributes.Resource == "deployments" && attributes.Verb != "get" && attributes.Verb != "list" {
			t.Fatal("read-only controller scope acquired application mutation permission", attributes)
		}
	}
	for scope, found := range wanted {
		if !found {
			t.Errorf("required current %s read was missing from the permission plan", scope)
		}
	}
}

func TestGitOpsStatelessChecksDoNotRequireUnusedPodInventory(t *testing.T) {
	e, requests := permissionServer(t, func(a authorizationv1.ResourceAttributes) authorizationv1.SubjectAccessReviewStatus {
		if a.Resource == "pods" {
			return authorizationv1.SubjectAccessReviewStatus{Denied: true}
		}
		return authorizationv1.SubjectAccessReviewStatus{Allowed: true}
	})
	p := spec.Plan{Header: spec.NewHeader("GitOpsChecksPlan"), GitOps: &spec.GitOpsPlanBinding{Contract: &spec.GitOpsProfileContract{Namespace: "argocd", Name: "application"}}, Checks: []spec.Check{{ID: "workflow", Type: "job"}}}
	for _, finding := range e.PermissionFindings(context.Background(), p, nil) {
		if finding.Severity == "blocker" {
			t.Fatal("restricted stateless identity was blocked", finding)
		}
	}
	for _, attributes := range requests() {
		if attributes.Resource == "pods" {
			t.Fatal("unused Pod permission was requested", attributes)
		}
	}
}
