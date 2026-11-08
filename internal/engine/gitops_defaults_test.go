package engine

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestObserveGitOpsProfileDefaultedFieldWriters(t *testing.T) {
	for _, tc := range []struct {
		name   string
		object int
		path   []string
		value  any
	}{
		{"deployment-replicas", 0, []string{"spec", "replicas"}, int64(1)},
		{"service-session-affinity", 1, []string{"spec", "sessionAffinity"}, "None"},
		{"configmap-immutable", 2, []string{"immutable"}, false},
	} {
		for _, operation := range []string{"", "Apply", "Update"} {
			name := operation
			if name == "" {
				name = "ordinary-api-default"
			}
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				f := newProfileFixture(t)
				objects, err := PermissionObjects(f.manifest)
				if err != nil {
					t.Fatal(err)
				}
				unstructured.RemoveNestedField(objects[tc.object], tc.path...)
				objects[0]["metadata"].(map[string]any)["labels"].(map[string]any)["reviewed-default"] = "omitted"
				base := f.v.Index.Lock.Release.Spec.Deployment.GitOps.Revision
				f.reviewObjects(t, objects)
				f.v.Index.Lock.Release.Spec.Deployment.GitOps.Revision = base
				profileSet(t, f.live[0], "omitted", "metadata", "labels", "reviewed-default")
				u := f.live[tc.object]
				profileSet(t, u, tc.value, tc.path...)
				entries, _, err := unstructured.NestedSlice(u.Object, "metadata", "managedFields")
				if err != nil {
					t.Fatal(err)
				}
				path := make([]string, len(tc.path))
				for i, part := range tc.path {
					path[i] = "f:" + part
				}
				unstructured.RemoveNestedField(entries[0].(map[string]any)["fieldsV1"].(map[string]any), path...)
				if operation != "" {
					fields := map[string]any{}
					if err := unstructured.SetNestedMap(fields, map[string]any{}, path...); err != nil {
						t.Fatal(err)
					}
					entries = append(entries, map[string]any{"manager": "other-controller", "operation": operation, "apiVersion": u.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": fields})
				}
				profileSet(t, u, entries, "metadata", "managedFields")
				f.seed(t)
				if operation != "" {
					f.denied(t, "OWNERSHIP_MISMATCH")
					return
				}
				o, err := f.observe()
				if err != nil || !o.Ready {
					t.Fatalf("ordinary omitted API default rejected: %v %#v", err, o.Findings)
				}
				if o.ApplicationAcceptance != "not_established" {
					t.Fatal("controller observation claimed application acceptance")
				}
				f.assertReadOnly(t)
			})
		}
	}
}
