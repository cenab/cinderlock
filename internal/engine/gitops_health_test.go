package engine

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestObserveGitOpsProfileResourceHealthSource(t *testing.T) {
	for _, tc := range []struct {
		name, blocker string
	}{
		{"inline", ""},
		{"app-tree", ""},
		{"unknown-source", "INVENTORY_MISMATCH"},
		{"malformed-source", "INVENTORY_MISMATCH"},
		{"missing-inline-health", "INVENTORY_MISMATCH"},
		{"app-tree-contradictory-health", "INVENTORY_MISMATCH"},
		{"app-tree-unhealthy-application", "CONTROLLER_MISMATCH"},
		{"app-tree-unhealthy-deployment", "RESOURCE_UNHEALTHY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			if tc.name != "inline" {
				resources, _, err := unstructured.NestedSlice(f.application.Object, "status", "resources")
				if err != nil {
					t.Fatal(err)
				}
				if tc.name != "unknown-source" && tc.name != "malformed-source" {
					for _, value := range resources {
						delete(value.(map[string]any), "health")
					}
				}
				profileSet(t, f.application, "appTree", "status", "resourceHealthSource")
				switch tc.name {
				case "unknown-source":
					profileSet(t, f.application, "future-tree", "status", "resourceHealthSource")
				case "malformed-source":
					profileSet(t, f.application, false, "status", "resourceHealthSource")
				case "missing-inline-health":
					unstructured.RemoveNestedField(f.application.Object, "status", "resourceHealthSource")
				case "app-tree-contradictory-health":
					resources[0].(map[string]any)["health"] = map[string]any{"status": "Degraded"}
				case "app-tree-unhealthy-application":
					profileSet(t, f.application, "Degraded", "status", "health", "status")
				case "app-tree-unhealthy-deployment":
					profileSet(t, f.live[0], int64(0), "status", "readyReplicas")
				}
				profileSet(t, f.application, resources, "status", "resources")
			}
			f.seed(t)
			if tc.blocker != "" {
				f.denied(t, tc.blocker)
				return
			}
			o, err := f.observe()
			if err != nil || !o.Ready || !o.Resources[0].Healthy || o.ApplicationAcceptance != "not_established" {
				t.Fatalf("healthy resource representation rejected: %v %#v", err, o)
			}
			if tc.name == "app-tree" && o.Resources[0].ControllerHealth != "" {
				t.Fatal("app-tree observation invented inline resource health")
			}
			f.assertReadOnly(t)
		})
	}
}
