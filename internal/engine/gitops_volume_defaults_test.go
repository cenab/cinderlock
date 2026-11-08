package engine

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
)

func TestObserveGitOpsProfileVolumeFileModeDefaults(t *testing.T) {
	for _, source := range []struct {
		kind   string
		fields map[string]any
	}{
		{"configMap", map[string]any{"name": "settings"}},
		{"secret", map[string]any{"secretName": "credentials"}},
		{"downwardAPI", map[string]any{"items": []any{map[string]any{"path": "name", "fieldRef": map[string]any{"apiVersion": "v1", "fieldPath": "metadata.name"}}}}},
		{"projected", map[string]any{"sources": []any{map[string]any{"configMap": map[string]any{"name": "settings"}}}}},
	} {
		for _, mode := range []string{"api-default", "explicit-default", "explicit-other", "default-drift", "explicit-drift"} {
			t.Run(source.kind+"/"+mode, func(t *testing.T) {
				f := normalizedDeploymentProfile(t, func(pod map[string]any) {
					fields := runtime.DeepCopyJSON(source.fields)
					if mode == "explicit-default" {
						fields["defaultMode"] = int64(0644)
					}
					if mode == "explicit-other" || mode == "explicit-drift" {
						fields["defaultMode"] = int64(0600)
					}
					pod["volumes"] = []any{map[string]any{"name": "settings", source.kind: fields}}
					pod["containers"].([]any)[0].(map[string]any)["volumeMounts"] = []any{map[string]any{"name": "settings", "mountPath": "/settings", "readOnly": true}}
				})
				pod := f.live[0].Object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
				fields := pod["volumes"].([]any)[0].(map[string]any)[source.kind].(map[string]any)
				fields["defaultMode"] = int64(0644)
				if mode == "explicit-other" || mode == "default-drift" {
					fields["defaultMode"] = int64(0600)
				}
				f.seed(t)
				if mode == "default-drift" || mode == "explicit-drift" {
					f.denied(t, "FIELDS_MISMATCH")
					return
				}
				o, err := f.observe()
				if err != nil || !o.Ready {
					t.Fatalf("unchanged volume file mode rejected: %v %#v", err, o.Findings)
				}
				f.assertReadOnly(t)
			})
		}
	}
}
