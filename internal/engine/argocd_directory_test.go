package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestObserveGitOpsProfileEmptyHydrationStatus(t *testing.T) {
	f := newProfileFixture(t)
	profileSet(t, f.application, map[string]any{}, "status", "sourceHydrator")
	f.seed(t)
	o, err := f.observe()
	if err != nil || !o.Ready {
		t.Fatalf("plain Directory Application with empty typed hydration status rejected: %v %#v", err, o.Findings)
	}
	profileSet(t, f.application, map[string]any{"currentOperation": map[string]any{"phase": "Succeeded"}}, "status", "sourceHydrator")
	f.seed(t)
	f.denied(t, "CONTROLLER_MISMATCH")
}

func TestObserveGitOpsProfileRequiresEffectiveDirectorySource(t *testing.T) {
	f := newProfileFixture(t)
	unstructured.RemoveNestedField(f.application.Object, "status", "sourceType")
	f.seed(t)
	f.denied(t, "CONTROLLER_MISMATCH")
}

func TestObserveGitOpsProfileAllowsDefaultHookStrategyWithoutHooks(t *testing.T) {
	f := newProfileFixture(t)
	profileSet(t, f.application, map[string]any{"hook": map[string]any{}}, "status", "operationState", "operation", "sync", "syncStrategy")
	f.seed(t)
	observed, err := f.observe()
	if err != nil || !observed.Ready {
		t.Fatalf("known no-hook sync strategy rejected: %v %#v", err, observed.Findings)
	}
}

func TestObserveGitOpsProfileRequiresDeclaredServerSideApply(t *testing.T) {
	f := newProfileFixture(t)
	unstructured.RemoveNestedField(f.application.Object, "spec", "syncPolicy", "syncOptions")
	f.seed(t)
	f.denied(t, "CONTROLLER_MISMATCH")
}

func TestObserveGitOpsProfileControllerDenials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []string
		value  any
	}{
		{"wrong-uid", []string{"metadata", "uid"}, "other-uid"},
		{"wrong-name", []string{"metadata", "name"}, "other"},
		{"wrong-namespace", []string{"metadata", "namespace"}, "other"},
		{"missing-resource-version", []string{"metadata", "resourceVersion"}, ""},
		{"missing-generation", []string{"metadata", "generation"}, int64(0)},
		{"deleting", []string{"metadata", "deletionTimestamp"}, time.Now().UTC().Format(time.RFC3339)},
		{"pending-operation", []string{"operation"}, map[string]any{"sync": map[string]any{}}},
		{"empty-pending-operation", []string{"operation"}, map[string]any{}},
		{"malformed-empty-conditions", []string{"status", "conditions"}, ""},
		{"malformed-empty-revisions", []string{"status", "sync", "revisions"}, ""},
		{"wrong-reported-source-type", []string{"status", "sourceType"}, "Helm"},
		{"condition", []string{"status", "conditions"}, []any{map[string]any{"type": "ComparisonError", "message": "STATUS-SENSITIVE-SENTINEL"}}},
		{"warning", []string{"status", "warnings"}, []any{"STATUS-SENSITIVE-SENTINEL"}},
		{"wrong-source", []string{"spec", "source", "repoURL"}, "https://user:PRODUCER-CREDENTIAL-SENTINEL@git.example.invalid/private.git"},
		{"moving-source-revision", []string{"spec", "source", "targetRevision"}, "main"},
		{"wrong-source-path", []string{"spec", "source", "path"}, "other"},
		{"glob-include", []string{"spec", "source", "directory", "include"}, "*.yaml"},
		{"recursive-directory", []string{"spec", "source", "directory", "recurse"}, true},
		{"excluded-directory", []string{"spec", "source", "directory", "exclude"}, "other.yaml"},
		{"jsonnet", []string{"spec", "source", "directory", "jsonnet"}, map[string]any{}},
		{"unknown-directory-behavior", []string{"spec", "source", "directory", "futureRenderer"}, true},
		{"helm", []string{"spec", "source", "helm"}, map[string]any{}},
		{"kustomize", []string{"spec", "source", "kustomize"}, map[string]any{}},
		{"plugin", []string{"spec", "source", "plugin"}, map[string]any{"name": "custom"}},
		{"chart", []string{"spec", "source", "chart"}, "app"},
		{"ref", []string{"spec", "source", "ref"}, "values"},
		{"multisource", []string{"spec", "sources"}, []any{}},
		{"hydrator", []string{"spec", "sourceHydrator"}, map[string]any{}},
		{"ignore-differences", []string{"spec", "ignoreDifferences"}, []any{}},
		{"remote-destination", []string{"spec", "destination", "server"}, "https://remote.invalid"},
		{"destination-name", []string{"spec", "destination", "name"}, "in-cluster"},
		{"wrong-destination-namespace", []string{"spec", "destination", "namespace"}, "other"},
		{"wrong-compared-source", []string{"status", "sync", "comparedTo", "source", "repoURL"}, "https://user:PRODUCER-CREDENTIAL-SENTINEL@git.example.invalid/private.git"},
		{"wrong-compared-destination", []string{"status", "sync", "comparedTo", "destination", "namespace"}, "other"},
		{"compared-multisource", []string{"status", "sync", "comparedTo", "sources"}, []any{}},
		{"compared-ignore-rules", []string{"status", "sync", "comparedTo", "ignoreDifferences"}, []any{}},
		{"wrong-observed-revision", []string{"status", "sync", "revision"}, strings.Repeat("d", 40)},
		{"opaque-observed-revision", []string{"status", "sync", "revision"}, "STATUS-SENSITIVE-SENTINEL"},
		{"not-synced", []string{"status", "sync", "status"}, "OutOfSync"},
		{"unknown-health", []string{"status", "health", "status"}, "STATUS-SENSITIVE-SENTINEL"},
		{"failed-operation", []string{"status", "operationState", "phase"}, "STATUS-SENSITIVE-SENTINEL"},
		{"wrong-operation-revision", []string{"status", "operationState", "syncResult", "revision"}, strings.Repeat("d", 40)},
		{"wrong-operation-source", []string{"status", "operationState", "syncResult", "source", "repoURL"}, "https://user:PRODUCER-CREDENTIAL-SENTINEL@git.example.invalid/private.git"},
		{"request-source-override", []string{"status", "operationState", "operation", "sync", "source"}, map[string]any{}},
		{"request-manifest-override", []string{"status", "operationState", "operation", "sync", "manifests"}, []any{"STATUS-SENSITIVE-SENTINEL"}},
		{"selective-sync", []string{"status", "operationState", "operation", "sync", "resources"}, []any{map[string]any{"name": "app"}}},
		{"dry-run-sync", []string{"status", "operationState", "operation", "sync", "dryRun"}, true},
		{"force-apply", []string{"status", "operationState", "operation", "sync", "syncStrategy"}, map[string]any{"apply": map[string]any{"force": true}}},
		{"force-hook-strategy", []string{"status", "operationState", "operation", "sync", "syncStrategy"}, map[string]any{"hook": map[string]any{"force": true}}},
		{"unknown-sync-option", []string{"spec", "syncPolicy", "syncOptions"}, []any{"Validate=false"}},
		{"unsafe-operation-option", []string{"status", "operationState", "operation", "sync", "syncOptions"}, []any{"Replace=true"}},
		{"namespace-creation", []string{"spec", "syncPolicy", "managedNamespaceMetadata"}, map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			profileSet(t, f.application, tc.value, tc.fields...)
			f.seed(t)
			if tc.name == "wrong-name" || tc.name == "wrong-namespace" {
				f.client.PrependReactor("get", "applications", func(ktesting.Action) (bool, runtime.Object, error) { return true, f.application.DeepCopy(), nil })
			}
			f.denied(t, "CONTROLLER_MISMATCH")
		})
	}
}

func TestObserveGitOpsProfileOriginalTimeDenials(t *testing.T) {
	for _, field := range []string{"reconciledAt", "startedAt", "finishedAt"} {
		for _, problem := range []string{"missing", "malformed", "future", "stale", "before-notBefore"} {
			t.Run(field+"/"+problem, func(t *testing.T) {
				f := newProfileFixture(t)
				fields := []string{"status", "operationState", field}
				if field == "reconciledAt" {
					fields = []string{"status", field}
				}
				value := ""
				switch problem {
				case "malformed":
					value = "STATUS-SENSITIVE-SENTINEL"
				case "future":
					value = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
				case "stale":
					value = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
					f.contract.NotBefore = time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339Nano)
				case "before-notBefore":
					value = time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339Nano)
				}
				profileSet(t, f.application, value, fields...)
				f.seed(t)
				f.denied(t, "CONTROLLER_MISMATCH")
			})
		}
	}
	for _, field := range []string{"startedAt", "finishedAt"} {
		t.Run("unordered/"+field, func(t *testing.T) {
			f := newProfileFixture(t)
			profileSet(t, f.application, time.Now().Add(-30*time.Second).UTC().Format(time.RFC3339Nano), "status", "operationState", field)
			f.seed(t)
			f.denied(t, "CONTROLLER_MISMATCH")
		})
	}
}

func TestObserveGitOpsProfileInventoryDenials(t *testing.T) {
	for _, operation := range []bool{false, true} {
		for _, problem := range []string{"missing", "extra", "duplicate", "wrong-namespace", "wrong-version", "not-synced", "hook", "phase", "prune-pending", "deletion-confirmation", "nonzero-wave", "deployment-health", "nonworkload-health"} {
			if operation && (problem == "prune-pending" || problem == "deletion-confirmation" || problem == "nonzero-wave" || strings.HasSuffix(problem, "health")) {
				continue
			}
			if !operation && problem == "phase" {
				continue
			}
			t.Run(fmt.Sprintf("operation=%v/%s", operation, problem), func(t *testing.T) {
				f := newProfileFixture(t)
				fields := []string{"status", "resources"}
				if operation {
					fields = []string{"status", "operationState", "syncResult", "resources"}
				}
				resources, _, err := unstructured.NestedSlice(f.application.Object, fields...)
				if err != nil {
					t.Fatal(err)
				}
				first := resources[0].(map[string]any)
				switch problem {
				case "missing":
					resources = resources[:2]
				case "extra":
					extra := runtime.DeepCopyJSON(first)
					extra["name"] = "extra"
					resources = append(resources, extra)
				case "duplicate":
					resources[1] = runtime.DeepCopyJSON(first)
				case "wrong-namespace":
					first["namespace"] = "other"
				case "wrong-version":
					first["version"] = "v1beta1"
				case "not-synced":
					first["status"] = "PruneSkipped"
				case "hook":
					if operation {
						first["hookType"] = "PreSync"
					} else {
						first["hook"] = true
					}
				case "phase":
					first["syncPhase"] = "PostSync"
				case "prune-pending":
					first["requiresPruning"] = true
				case "deletion-confirmation":
					first["requiresDeletionConfirmation"] = true
				case "nonzero-wave":
					first["syncWave"] = int64(1)
				case "deployment-health":
					delete(first, "health")
				case "nonworkload-health":
					resources[1].(map[string]any)["health"] = map[string]any{"status": "STATUS-SENSITIVE-SENTINEL"}
				}
				profileSet(t, f.application, resources, fields...)
				f.seed(t)
				f.denied(t, "INVENTORY_MISMATCH")
			})
		}
	}
	for _, phase := range []string{"Running", "Failed", "STATUS-SENSITIVE-SENTINEL"} {
		t.Run("unresolved-hook-phase/"+phase, func(t *testing.T) {
			f := newProfileFixture(t)
			results, _, _ := unstructured.NestedSlice(f.application.Object, "status", "operationState", "syncResult", "resources")
			results[0].(map[string]any)["hookType"] = "Sync"
			results[0].(map[string]any)["hookPhase"] = phase
			profileSet(t, f.application, results, "status", "operationState", "syncResult", "resources")
			f.seed(t)
			f.denied(t, "INVENTORY_MISMATCH")
		})
	}
}
