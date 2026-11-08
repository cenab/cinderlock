package engine

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestObserveGitOpsProfileNormalApplyResultPhase(t *testing.T) {
	for _, tc := range []struct {
		name, blocker string
	}{
		{"completed-app-tree", ""},
		{"completed-inline", ""},
		{"actual-hook", "INVENTORY_MISMATCH"},
		{"incomplete-operation", "CONTROLLER_MISMATCH"},
		{"failed-resource-phase", "INVENTORY_MISMATCH"},
		{"unhealthy-live-deployment", "RESOURCE_UNHEALTHY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			results, _, err := unstructured.NestedSlice(f.application.Object, "status", "operationState", "syncResult", "resources")
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range results {
				value.(map[string]any)["hookPhase"] = "Running"
			}
			if tc.name != "completed-inline" {
				resources, _, err := unstructured.NestedSlice(f.application.Object, "status", "resources")
				if err != nil {
					t.Fatal(err)
				}
				for _, value := range resources {
					delete(value.(map[string]any), "health")
				}
				profileSet(t, f.application, resources, "status", "resources")
				profileSet(t, f.application, "appTree", "status", "resourceHealthSource")
			}
			switch tc.name {
			case "actual-hook":
				results[0].(map[string]any)["hookType"] = "Sync"
			case "incomplete-operation":
				profileSet(t, f.application, "Running", "status", "operationState", "phase")
			case "failed-resource-phase":
				results[0].(map[string]any)["hookPhase"] = "Failed"
			case "unhealthy-live-deployment":
				profileSet(t, f.live[0], int64(0), "status", "readyReplicas")
			}
			profileSet(t, f.application, results, "status", "operationState", "syncResult", "resources")
			f.seed(t)
			if tc.blocker != "" {
				f.denied(t, tc.blocker)
				return
			}
			o, err := f.observe()
			if err != nil || !o.Ready || o.ApplicationAcceptance != "not_established" {
				t.Fatalf("completed ordinary apply rejected: %v %#v", err, o.Findings)
			}
			f.assertReadOnly(t)
		})
	}
}
