package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestObserveGitOpsProfileDefaultedServiceFieldOwnership(t *testing.T) {
	f := newProfileFixture(t)
	service := f.live[1]
	ports, _, _ := unstructured.NestedSlice(service.Object, "spec", "ports")
	ports[0].(map[string]any)["protocol"] = "TCP"
	profileSet(t, service, ports, "spec", "ports")
	entries, _, _ := unstructured.NestedSlice(service.Object, "metadata", "managedFields")
	entries[0].(map[string]any)["fieldsV1"].(map[string]any)["f:spec"] = map[string]any{
		"f:type": map[string]any{}, "f:selector": map[string]any{},
		"f:ports": map[string]any{`k:{"port":80,"protocol":"TCP"}`: map[string]any{
			".": map[string]any{}, "f:port": map[string]any{}, "f:targetPort": map[string]any{},
		}},
	}
	profileSet(t, service, entries, "metadata", "managedFields")
	f.seed(t)
	o, err := f.observe()
	if err != nil || !o.Ready {
		t.Fatalf("Kubernetes defaulted Service SSA list key rejected: %v %#v", err, o.Findings)
	}
}

func TestObserveGitOpsProfileParentMapMembershipDoesNotOwnKeys(t *testing.T) {
	f := newProfileFixture(t)
	entries, _, _ := unstructured.NestedSlice(f.live[2].Object, "metadata", "managedFields")
	entries[0].(map[string]any)["fieldsV1"].(map[string]any)["f:data"] = map[string]any{}
	profileSet(t, f.live[2], entries, "metadata", "managedFields")
	f.seed(t)
	f.denied(t, "OWNERSHIP_MISMATCH")
}

func TestObserveGitOpsProfileHeadlessServiceRequiresReview(t *testing.T) {
	for _, field := range []string{"clusterIP", "clusterIPs"} {
		t.Run(field, func(t *testing.T) {
			f := newProfileFixture(t)
			var value any = "None"
			if field == "clusterIPs" {
				value = []any{"None"}
			}
			profileSet(t, f.live[1], value, "spec", field)
			f.seed(t)
			f.denied(t, "FIELDS_MISMATCH")
		})
	}
	t.Run("explicit-reviewed-headless", func(t *testing.T) {
		f := newProfileFixture(t)
		objects, err := PermissionObjects(f.manifest)
		if err != nil {
			t.Fatal(err)
		}
		objects[1]["spec"].(map[string]any)["clusterIP"] = "None"
		f.reviewObjects(t, objects)
		profileSet(t, f.live[1], []any{"None"}, "spec", "clusterIPs")
		f.seed(t)
		o, err := f.observe()
		if err != nil || !o.Ready {
			t.Fatalf("explicitly reviewed headless Service rejected: %v %#v", err, o.Findings)
		}
	})
}

func TestObserveGitOpsProfileAllowsReviewedHelmTemplateLabels(t *testing.T) {
	f := newProfileFixture(t)
	objects, err := PermissionObjects(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	labels := objects[0]["metadata"].(map[string]any)["labels"].(map[string]any)
	labels["app.kubernetes.io/managed-by"], labels["helm.sh/chart"] = "Helm", "application-2.0.0"
	f.reviewObjects(t, objects)
	current := f.live[0].GetLabels()
	current["app.kubernetes.io/managed-by"], current["helm.sh/chart"] = "Helm", "application-2.0.0"
	f.live[0].SetLabels(current)
	f.seed(t)
	observed, err := f.observe()
	if err != nil || !observed.Ready {
		t.Fatalf("reviewed templated labels became an active Helm owner: %v %#v", err, observed.Findings)
	}
}

func TestObserveGitOpsProfileLiveFieldDrift(t *testing.T) {
	f := newProfileFixture(t)
	containers, _, err := unstructured.NestedSlice(f.live[0].Object, "spec", "template", "spec", "containers")
	if err != nil {
		t.Fatal(err)
	}
	containers[0].(map[string]any)["image"] = "registry.invalid/unreviewed@sha256:" + strings.Repeat("d", 64)
	if err = unstructured.SetNestedSlice(f.live[0].Object, containers, "spec", "template", "spec", "containers"); err != nil {
		t.Fatal(err)
	}
	f.seed(t)
	o, err := f.observe()
	if err != nil || o.Ready || !profileHasBlocker(o, "GITOPS_PROFILE_FIELDS_MISMATCH") {
		t.Fatalf("healthy controller concealed live image drift: err=%v ready=%v findings=%#v", err, o.Ready, o.Findings)
	}
	if len(o.Resources) != 3 || o.Resources[0].DesiredFieldsMatch || !o.Resources[0].Healthy || o.HealthStatus != "Healthy" {
		t.Fatalf("lost independent drift/health facts: %#v", o)
	}
	f.assertReadOnly(t)
}

func TestObserveGitOpsProfileLiveBehaviorDenials(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		index      int
		fields     []string
		value      any
	}{
		{"deployment-selector-extra", "FIELDS_MISMATCH", 0, []string{"spec", "selector", "matchLabels", "unreviewed"}, "true"},
		{"service-selector-extra", "FIELDS_MISMATCH", 1, []string{"spec", "selector", "unreviewed"}, "true"},
		{"configmap-extra-data", "FIELDS_MISMATCH", 2, []string{"data", "unreviewed"}, "CONFIGMAP-SENSITIVE-SENTINEL"},
		{"configmap-binary-data", "FIELDS_MISMATCH", 2, []string{"binaryData"}, map[string]any{"unreviewed": "c2VjcmV0"}},
		{"opaque-init-container", "RESOURCE_UNHEALTHY", 0, []string{"spec", "template", "spec", "initContainers"}, []any{map[string]any{"name": "unreviewed", "image": "registry.invalid/other"}}},
		{"opaque-ephemeral-container", "RESOURCE_UNHEALTHY", 0, []string{"spec", "template", "spec", "ephemeralContainers"}, []any{map[string]any{"name": "unreviewed", "image": "registry.invalid/other"}}},
		{"deployment-not-rolled-out", "RESOURCE_UNHEALTHY", 0, []string{"status", "availableReplicas"}, int64(0)},
		{"deployment-stale-status", "RESOURCE_UNHEALTHY", 0, []string{"status", "observedGeneration"}, int64(0)},
		{"service-nodeport", "RESOURCE_UNHEALTHY", 1, []string{"spec", "type"}, "NodePort"},
		{"service-load-balancer", "RESOURCE_UNHEALTHY", 1, []string{"spec", "type"}, "LoadBalancer"},
		{"service-external-name", "RESOURCE_UNHEALTHY", 1, []string{"spec", "externalName"}, "outside.invalid"},
		{"service-external-ip", "RESOURCE_UNHEALTHY", 1, []string{"spec", "externalIPs"}, []any{"192.0.2.1"}},
		{"service-lb-class", "RESOURCE_UNHEALTHY", 1, []string{"spec", "loadBalancerClass"}, "external"},
		{"service-healthcheck-route", "RESOURCE_UNHEALTHY", 1, []string{"spec", "healthCheckNodePort"}, int64(32000)},
		{"missing-uid", "RESOURCE_INACTIVE", 0, []string{"metadata", "uid"}, ""},
		{"missing-resource-version", "RESOURCE_INACTIVE", 1, []string{"metadata", "resourceVersion"}, ""},
		{"deleted-resource", "RESOURCE_INACTIVE", 2, []string{"metadata", "deletionTimestamp"}, time.Now().UTC().Format(time.RFC3339)},
		{"malformed-deletion-time", "RESOURCE_INACTIVE", 2, []string{"metadata", "deletionTimestamp"}, "STATUS-SENSITIVE-SENTINEL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			profileSet(t, f.live[tc.index], tc.value, tc.fields...)
			f.seed(t)
			f.denied(t, tc.code)
		})
	}
	for _, behavior := range []string{"lifecycle", "sidecar", "extra-env", "nodeport"} {
		t.Run(behavior, func(t *testing.T) {
			f := newProfileFixture(t)
			u, fields, code := f.live[0], []string{"spec", "template", "spec", "containers"}, "FIELDS_MISMATCH"
			if behavior == "nodeport" {
				u, fields, code = f.live[1], []string{"spec", "ports"}, "RESOURCE_UNHEALTHY"
			}
			items, _, err := unstructured.NestedSlice(u.Object, fields...)
			if err != nil {
				t.Fatal(err)
			}
			switch behavior {
			case "lifecycle":
				items[0].(map[string]any)["lifecycle"] = map[string]any{"postStart": map[string]any{"exec": map[string]any{"command": []any{"unreviewed"}}}}
				code = "RESOURCE_UNHEALTHY"
			case "sidecar":
				items = append(items, map[string]any{"name": "unreviewed", "image": "registry.invalid/sidecar"})
			case "extra-env":
				items[0].(map[string]any)["env"] = []any{map[string]any{"name": "UNREVIEWED", "value": "STATUS-SENSITIVE-SENTINEL"}}
			case "nodeport":
				items[0].(map[string]any)["nodePort"] = int64(32000)
			}
			profileSet(t, u, items, fields...)
			f.seed(t)
			f.denied(t, code)
		})
	}
}

func TestObserveGitOpsProfileKnownAPIDefaults(t *testing.T) {
	f := newProfileFixture(t)
	profileSet(t, f.live[0], int64(600), "spec", "progressDeadlineSeconds")
	profileSet(t, f.live[0], int64(10), "spec", "revisionHistoryLimit")
	profileSet(t, f.live[0], map[string]any{"type": "RollingUpdate", "rollingUpdate": map[string]any{"maxSurge": "25%", "maxUnavailable": "25%"}}, "spec", "strategy")
	profileSet(t, f.live[0], "Always", "spec", "template", "spec", "restartPolicy")
	profileSet(t, f.live[0], "ClusterFirst", "spec", "template", "spec", "dnsPolicy")
	profileSet(t, f.live[0], int64(30), "spec", "template", "spec", "terminationGracePeriodSeconds")
	items, _, _ := unstructured.NestedSlice(f.live[0].Object, "spec", "template", "spec", "containers")
	items[0].(map[string]any)["imagePullPolicy"] = "IfNotPresent"
	items[0].(map[string]any)["terminationMessagePath"] = "/dev/termination-log"
	profileSet(t, f.live[0], items, "spec", "template", "spec", "containers")
	profileSet(t, f.live[1], "10.0.0.7", "spec", "clusterIP")
	profileSet(t, f.live[1], []any{"10.0.0.7"}, "spec", "clusterIPs")
	profileSet(t, f.live[1], []any{"IPv4"}, "spec", "ipFamilies")
	profileSet(t, f.live[1], "SingleStack", "spec", "ipFamilyPolicy")
	profileSet(t, f.live[1], "None", "spec", "sessionAffinity")
	f.seed(t)
	o, err := f.observe()
	if err != nil || !o.Ready {
		t.Fatalf("known API defaults rejected: %v %#v", err, o.Findings)
	}
	f.assertReadOnly(t)
	f.assertWithheld(t, o, err)
}

func TestObserveGitOpsProfileOwnershipDenials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []string
		value  any
	}{
		{"missing-tracking", []string{"metadata", "annotations", "argocd.argoproj.io/tracking-id"}, ""},
		{"wrong-tracking", []string{"metadata", "annotations", "argocd.argoproj.io/tracking-id"}, "other:apps/Deployment:test/app"},
		{"wrong-installation", []string{"metadata", "annotations", "argocd.argoproj.io/installation-id"}, "other"},
		{"argo-label-other-application", []string{"metadata", "labels", "argocd.argoproj.io/instance"}, "other"},
		{"helm-release-annotation", []string{"metadata", "annotations", "meta.helm.sh/release-name"}, "app"},
		{"flux-kustomize", []string{"metadata", "labels", "kustomize.toolkit.fluxcd.io/name"}, "app"},
		{"flux-helm", []string{"metadata", "annotations", "helm.toolkit.fluxcd.io/name"}, "app"},
		{"argo-hook", []string{"metadata", "annotations", "argocd.argoproj.io/hook"}, "Sync"},
		{"argo-ignore", []string{"metadata", "annotations", "argocd.argoproj.io/compare-options"}, "IgnoreExtraneous"},
		{"argo-prune-confirm", []string{"metadata", "annotations", "argocd.argoproj.io/sync-options"}, "Prune=confirm"},
		{"argo-deletion-confirm", []string{"metadata", "annotations", "argocd.argoproj.io/deletion-approved"}, time.Now().UTC().Format(time.RFC3339)},
		{"argo-unknown", []string{"metadata", "annotations", "argocd.argoproj.io/future-behavior"}, "true"},
		{"argo-nonzero-wave", []string{"metadata", "annotations", "argocd.argoproj.io/sync-wave"}, "1"},
		{"other-finalizer", []string{"metadata", "finalizers"}, []any{"other.example/cleanup"}},
		{"other-owner", []string{"metadata", "ownerReferences"}, []any{map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": "other", "uid": "other-uid", "controller": true}}},
		{"missing-managed-fields", []string{"metadata", "managedFields"}, []any{}},
		{"malformed-managed-fields", []string{"metadata", "managedFields"}, "STATUS-SENSITIVE-SENTINEL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			profileSet(t, f.live[0], tc.value, tc.fields...)
			f.seed(t)
			f.denied(t, "OWNERSHIP_MISMATCH")
		})
	}
	for _, problem := range []string{"other-manager", "controller-update-without-apply", "competing-spec-writer", "competing-label-writer", "competing-configmap-writer", "incomplete-ownership", "duplicate-manager", "invalid-fieldset", "unknown-mixed-field-path", "wrong-api-version", "wrong-fields-type", "status-claiming-spec"} {
		t.Run(problem, func(t *testing.T) {
			f := newProfileFixture(t)
			u := f.live[0]
			if problem == "competing-configmap-writer" {
				u = f.live[2]
			}
			entries, _, err := unstructured.NestedSlice(u.Object, "metadata", "managedFields")
			if err != nil {
				t.Fatal(err)
			}
			first := entries[0].(map[string]any)
			switch problem {
			case "other-manager":
				first["manager"] = "other-controller"
			case "controller-update-without-apply":
				first["operation"] = "Update"
			case "competing-spec-writer", "competing-label-writer", "competing-configmap-writer", "status-claiming-spec":
				fields := map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}}}
				if problem == "competing-label-writer" {
					fields = map[string]any{"f:metadata": map[string]any{"f:labels": map[string]any{"f:app": map[string]any{}}}}
				}
				if problem == "competing-configmap-writer" {
					fields = map[string]any{"f:data": map[string]any{"f:setting": map[string]any{}}}
				}
				entry := map[string]any{"manager": "other-controller", "operation": "Update", "apiVersion": u.GetAPIVersion(), "fieldsType": "FieldsV1", "fieldsV1": fields}
				if problem == "status-claiming-spec" {
					entry["subresource"] = "status"
				}
				entries = append(entries, entry)
			case "incomplete-ownership":
				first["fieldsV1"].(map[string]any)["f:spec"] = map[string]any{"f:replicas": map[string]any{}}
			case "duplicate-manager":
				entries = append(entries, runtime.DeepCopyJSON(first))
			case "invalid-fieldset":
				first["fieldsV1"] = map[string]any{"invalid": map[string]any{}}
			case "unknown-mixed-field-path":
				first["fieldsV1"].(map[string]any)["x:opaque"] = map[string]any{}
			case "wrong-api-version":
				first["apiVersion"] = "apps/v1beta1"
			case "wrong-fields-type":
				first["fieldsType"] = "unknown"
			}
			profileSet(t, u, entries, "metadata", "managedFields")
			f.seed(t)
			f.denied(t, "OWNERSHIP_MISMATCH")
		})
	}
}

func TestObserveGitOpsProfileInvalidReviewedInventory(t *testing.T) {
	for _, change := range []string{"Secret", "Job", "PersistentVolumeClaim", "other-api-version", "generated-name", "cross-namespace", "hook", "init-container", "ephemeral-container", "lifecycle", "NodePort", "ExternalName", "duplicate", "over-limit", "empty", "status", "malformed-data", "unknown-spec-field"} {
		t.Run(change, func(t *testing.T) {
			f := newProfileFixture(t)
			objects, err := PermissionObjects(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			first := &unstructured.Unstructured{Object: objects[0]}
			switch change {
			case "Secret", "Job", "PersistentVolumeClaim":
				objects[0]["kind"] = change
			case "other-api-version":
				objects[0]["apiVersion"] = "apps/v1beta1"
			case "generated-name":
				objects[0]["metadata"].(map[string]any)["generateName"] = "app-"
			case "cross-namespace":
				objects[0]["metadata"].(map[string]any)["namespace"] = "other"
			case "hook":
				objects[0]["metadata"].(map[string]any)["annotations"] = map[string]any{"argocd.argoproj.io/hook": "PreSync"}
			case "init-container", "ephemeral-container":
				field := "initContainers"
				if change == "ephemeral-container" {
					field = "ephemeralContainers"
				}
				profileSet(t, first, []any{map[string]any{"name": "unreviewed", "image": "unreviewed"}}, "spec", "template", "spec", field)
			case "lifecycle":
				pod := objects[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
				pod["containers"].([]any)[0].(map[string]any)["lifecycle"] = map[string]any{"preStop": map[string]any{"exec": map[string]any{"command": []any{"unreviewed"}}}}
			case "NodePort", "ExternalName":
				objects[1]["spec"].(map[string]any)["type"] = change
			case "duplicate":
				objects = append(objects, objects[0])
			case "over-limit":
				for len(objects) < 65 {
					objects = append(objects, objects[0])
				}
			case "empty":
				objects = nil
			case "status":
				objects[0]["status"] = map[string]any{"replicas": int64(1)}
			case "malformed-data":
				objects[2]["data"].(map[string]any)["setting"] = map[string]any{"opaque": "CONFIGMAP-SENSITIVE-SENTINEL"}
			case "unknown-spec-field":
				objects[0]["spec"].(map[string]any)["unqualifiedBehavior"] = true
			}
			if objects == nil {
				f.manifest = nil
			} else {
				f.manifest, err = encodeObjects(objects)
				if err != nil {
					t.Fatal(err)
				}
			}
			f.contract.ManifestDigest = spec.Hash(f.manifest)
			o, err := f.observe()
			if spec.ExitCode(err) != 2 || o.Ready {
				t.Fatalf("unsupported reviewed inventory admitted: %v %#v", err, o.Findings)
			}
			f.assertReadOnly(t)
			f.assertWithheld(t, o, err)
		})
	}
}

func TestObserveGitOpsProfileListsKeepLengthAndOrder(t *testing.T) {
	for _, variant := range []string{"matching", "reordered", "truncated"} {
		t.Run(variant, func(t *testing.T) {
			f := newProfileFixture(t)
			objects, err := PermissionObjects(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			containers := objects[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
			containers[0].(map[string]any)["env"] = []any{map[string]any{"name": "FIRST", "value": "one"}, map[string]any{"name": "SECOND", "value": "two"}}
			f.reviewObjects(t, objects)
			entries, _, _ := unstructured.NestedSlice(f.live[0].Object, "metadata", "managedFields")
			fields := entries[0].(map[string]any)["fieldsV1"].(map[string]any)
			container := fields["f:spec"].(map[string]any)["f:template"].(map[string]any)["f:spec"].(map[string]any)["f:containers"].(map[string]any)[`k:{"name":"app"}`].(map[string]any)
			container["f:env"] = map[string]any{`k:{"name":"FIRST"}`: map[string]any{".": map[string]any{}, "f:name": map[string]any{}, "f:value": map[string]any{}}, `k:{"name":"SECOND"}`: map[string]any{".": map[string]any{}, "f:name": map[string]any{}, "f:value": map[string]any{}}}
			profileSet(t, f.live[0], entries, "metadata", "managedFields")
			f.seed(t)
			if variant != "matching" {
				items, _, _ := unstructured.NestedSlice(f.live[0].Object, "spec", "template", "spec", "containers")
				env := items[0].(map[string]any)["env"].([]any)
				if variant == "reordered" {
					env[0], env[1] = env[1], env[0]
				} else {
					env = env[:1]
				}
				items[0].(map[string]any)["env"] = env
				profileSet(t, f.live[0], items, "spec", "template", "spec", "containers")
				f.seed(t)
				f.denied(t, "FIELDS_MISMATCH")
				return
			}
			o, err := f.observe()
			if err != nil || !o.Ready {
				t.Fatalf("reviewed ordered list rejected: %v %#v", err, o.Findings)
			}
			f.assertReadOnly(t)
		})
	}
}
