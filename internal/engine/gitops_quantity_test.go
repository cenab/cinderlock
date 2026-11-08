package engine

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func normalizedDeploymentProfile(t *testing.T, edit func(map[string]any)) *profileFixture {
	t.Helper()
	f := newProfileFixture(t)
	objects, err := PermissionObjects(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	edit(objects[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any))
	base := f.v.Index.Lock.Release.Spec.Deployment.GitOps.Revision
	f.reviewObjects(t, objects)
	f.v.Index.Lock.Release.Spec.Deployment.GitOps.Revision = base
	claim := &unstructured.Unstructured{Object: objects[0]}
	claim.SetAnnotations(f.live[0].GetAnnotations())
	typed, err := gitOpsFieldConverter.ObjectToTyped(claim)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := typed.ToFieldSet()
	if err != nil {
		t.Fatal(err)
	}
	body, err := fields.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	profileSet(t, f.live[0], []any{map[string]any{"manager": "argocd-controller", "operation": "Apply", "apiVersion": "apps/v1", "fieldsType": "FieldsV1", "fieldsV1": raw}}, "metadata", "managedFields")
	body, err = json.Marshal(f.live[0].Object)
	if err != nil {
		t.Fatal(err)
	}
	var deployment appsv1.Deployment
	if err := json.Unmarshal(body, &deployment); err != nil {
		t.Fatal(err)
	}
	body, err = json.Marshal(&deployment)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.live[0].UnmarshalJSON(body); err != nil {
		t.Fatal(err)
	}
	f.seed(t)
	return f
}

func TestObserveGitOpsProfileQuantityComparisonGuards(t *testing.T) {
	for _, change := range []string{"real-drift", "real-limit-drift", "missing-quantity", "missing-empty-map", "missing-list", "longer-list", "reordered-list", "ordinary-string", "unknown-key", "null-object", "equivalent-source-edit"} {
		t.Run(change, func(t *testing.T) {
			f := normalizedDeploymentProfile(t, func(pod map[string]any) {
				container := pod["containers"].([]any)[0].(map[string]any)
				container["resources"] = map[string]any{"requests": map[string]any{"cpu": "1000m"}, "limits": map[string]any{"memory": "1024Mi"}}
				container["env"] = []any{map[string]any{"name": "A", "value": "1000m"}, map[string]any{"name": "B", "value": "unchanged"}}
				pod["securityContext"] = map[string]any{}
				if change == "null-object" {
					container["resources"] = nil
					pod["resources"] = map[string]any{"requests": map[string]any{"cpu": "1000m"}}
				}
			})
			pod := f.live[0].Object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
			container := pod["containers"].([]any)[0].(map[string]any)
			env := container["env"].([]any)
			switch change {
			case "real-drift":
				container["resources"].(map[string]any)["requests"].(map[string]any)["cpu"] = "2"
			case "real-limit-drift":
				container["resources"].(map[string]any)["limits"].(map[string]any)["memory"] = "2Gi"
			case "missing-quantity":
				delete(container["resources"].(map[string]any)["requests"].(map[string]any), "cpu")
			case "missing-empty-map":
				delete(pod, "securityContext")
			case "missing-list":
				delete(container, "env")
			case "longer-list":
				container["env"] = append(env, map[string]any{"name": "C", "value": "extra"})
			case "reordered-list":
				env[0], env[1] = env[1], env[0]
			case "ordinary-string":
				env[0].(map[string]any)["value"] = "1"
			case "unknown-key":
				pod["futureBehavior"] = true
			case "equivalent-source-edit":
				f.manifest = bytes.ReplaceAll(f.manifest, []byte("1024Mi"), []byte("1Gi"))
				f.contract.ManifestDigest = spec.Hash(f.manifest)
				if o, err := f.observe(); spec.ExitCode(err) != 2 || o.Ready {
					t.Fatalf("equivalent source edit escaped exact render binding: %v %#v", err, o.Findings)
				}
				return
			}
			f.seed(t)
			f.denied(t, "FIELDS_MISMATCH")
		})
	}
}

func TestGitOpsProfileConfigMapStringsRemainExact(t *testing.T) {
	desired := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "config"}, "data": map[string]any{"setting": "1000m"}}
	live := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "config"}, "data": map[string]any{"setting": "1"}}
	if gitOpsProfileFieldsMatch(desired, live) {
		t.Fatal("quantity-like configuration strings were normalized")
	}
}

func TestObserveGitOpsProfileQuantityNormalization(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cpu, memory any
	}{
		{"canonical", "1", "1Gi"},
		{"normalized", "1000m", "1024Mi"},
		{"numeric", int64(1), "1024Mi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := normalizedDeploymentProfile(t, func(pod map[string]any) {
				pod["containers"].([]any)[0].(map[string]any)["resources"] = map[string]any{"requests": map[string]any{"cpu": tc.cpu}, "limits": map[string]any{"memory": tc.memory}}
			})
			o, err := f.observe()
			if err != nil || !o.Ready || !o.Resources[0].DesiredFieldsMatch {
				t.Fatalf("equivalent Kubernetes quantities rejected: %v %#v", err, o.Findings)
			}
			f.assertReadOnly(t)
		})
	}
}

func TestObserveGitOpsProfileQuantityLocations(t *testing.T) {
	f := normalizedDeploymentProfile(t, func(pod map[string]any) {
		pod["resources"] = map[string]any{"requests": map[string]any{"cpu": "1000m"}, "limits": map[string]any{"memory": "1024Mi"}}
		pod["overhead"] = map[string]any{"memory": "1024Mi"}
		pod["containers"].([]any)[0].(map[string]any)["env"] = []any{map[string]any{"name": "CPU", "valueFrom": map[string]any{"resourceFieldRef": map[string]any{"resource": "limits.cpu", "divisor": "1000m"}}}}
		item := map[string]any{"path": "cpu", "resourceFieldRef": map[string]any{"containerName": "app", "resource": "limits.cpu", "divisor": "1000m"}}
		pod["volumes"] = []any{
			map[string]any{"name": "scratch", "emptyDir": map[string]any{"sizeLimit": "1024Mi"}},
			map[string]any{"name": "ephemeral", "ephemeral": map[string]any{"volumeClaimTemplate": map[string]any{"metadata": map[string]any{}, "spec": map[string]any{"accessModes": []any{"ReadWriteOnce"}, "resources": map[string]any{"requests": map[string]any{"storage": "1024Mi"}, "limits": map[string]any{"storage": "1024Mi"}}}}}},
			map[string]any{"name": "downward", "downwardAPI": map[string]any{"defaultMode": int64(420), "items": []any{item}}},
			map[string]any{"name": "projected", "projected": map[string]any{"defaultMode": int64(420), "sources": []any{map[string]any{"downwardAPI": map[string]any{"items": []any{item}}}}}},
		}
	})
	o, err := f.observe()
	if err != nil || !o.Ready {
		t.Fatalf("equivalent quantities at supported API locations rejected: %v %#v", err, o.Findings)
	}
	original := f.live[0]
	for _, tc := range []struct {
		name string
		edit func(*corev1.PodSpec)
	}{
		{"pod-request", func(p *corev1.PodSpec) { p.Resources.Requests[corev1.ResourceCPU] = resource.MustParse("2") }},
		{"pod-limit", func(p *corev1.PodSpec) { p.Resources.Limits[corev1.ResourceMemory] = resource.MustParse("2Gi") }},
		{"overhead", func(p *corev1.PodSpec) { p.Overhead[corev1.ResourceMemory] = resource.MustParse("2Gi") }},
		{"env-divisor", func(p *corev1.PodSpec) {
			p.Containers[0].Env[0].ValueFrom.ResourceFieldRef.Divisor = resource.MustParse("2")
		}},
		{"emptydir-limit", func(p *corev1.PodSpec) {
			q := resource.MustParse("2Gi")
			p.Volumes[0].EmptyDir.SizeLimit = &q
		}},
		{"ephemeral-request", func(p *corev1.PodSpec) {
			p.Volumes[1].Ephemeral.VolumeClaimTemplate.Spec.Resources.Requests[corev1.ResourceStorage] = resource.MustParse("2Gi")
		}},
		{"ephemeral-limit", func(p *corev1.PodSpec) {
			p.Volumes[1].Ephemeral.VolumeClaimTemplate.Spec.Resources.Limits[corev1.ResourceStorage] = resource.MustParse("2Gi")
		}},
		{"downward-divisor", func(p *corev1.PodSpec) {
			p.Volumes[2].DownwardAPI.Items[0].ResourceFieldRef.Divisor = resource.MustParse("2")
		}},
		{"projected-divisor", func(p *corev1.PodSpec) {
			p.Volumes[3].Projected.Sources[0].DownwardAPI.Items[0].ResourceFieldRef.Divisor = resource.MustParse("2")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(original.Object)
			if err != nil {
				t.Fatal(err)
			}
			var deployment appsv1.Deployment
			if err := json.Unmarshal(body, &deployment); err != nil {
				t.Fatal(err)
			}
			tc.edit(&deployment.Spec.Template.Spec)
			body, err = json.Marshal(&deployment)
			if err != nil {
				t.Fatal(err)
			}
			f.live[0] = &unstructured.Unstructured{}
			if err := f.live[0].UnmarshalJSON(body); err != nil {
				t.Fatal(err)
			}
			f.seed(t)
			f.denied(t, "FIELDS_MISMATCH")
		})
	}
}
