package engine

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestObserveGitOpsProfileStatusRevisionBookkeeping(t *testing.T) {
	revision := []string{"f:metadata", "f:annotations", "f:deployment.kubernetes.io/revision"}
	for _, tc := range []struct {
		name, manager, operation string
		object                   int
		claim                    []string
		allowed                  bool
	}{
		{"status-only", "other-status-controller", "Update", 0, nil, true},
		{"deployment-revision", "kube-controller-manager", "Update", 0, revision, true},
		{"other-manager", "other-controller", "Update", 0, revision, false},
		{"apply-operation", "kube-controller-manager", "Apply", 0, revision, false},
		{"other-kind", "kube-controller-manager", "Update", 2, revision, false},
		{"spec-claim", "kube-controller-manager", "Update", 0, []string{"f:spec", "f:replicas"}, false},
		{"tracking-claim", "kube-controller-manager", "Update", 0, []string{"f:metadata", "f:annotations", "f:argocd.argoproj.io/tracking-id"}, false},
		{"other-metadata", "kube-controller-manager", "Update", 0, []string{"f:metadata", "f:labels", "f:app"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			u := f.live[tc.object]
			entries, _, err := unstructured.NestedSlice(u.Object, "metadata", "managedFields")
			if err != nil {
				t.Fatal(err)
			}
			fields := map[string]any{"f:status": map[string]any{"f:replicas": map[string]any{}}}
			if tc.claim != nil {
				if err := unstructured.SetNestedMap(fields, map[string]any{}, tc.claim...); err != nil {
					t.Fatal(err)
				}
			}
			entries = append(entries, map[string]any{"manager": tc.manager, "operation": tc.operation, "subresource": "status", "apiVersion": u.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": fields})
			profileSet(t, u, entries, "metadata", "managedFields")
			f.seed(t)
			if !tc.allowed {
				f.denied(t, "OWNERSHIP_MISMATCH")
				return
			}
			o, err := f.observe()
			if err != nil || !o.Ready {
				t.Fatalf("qualified status bookkeeping rejected: %v %#v", err, o.Findings)
			}
			f.assertReadOnly(t)
		})
	}
}
