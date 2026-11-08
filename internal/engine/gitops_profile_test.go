package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestObserveGitOpsProfileReady(t *testing.T) {
	f := newProfileFixture(t)
	before := repositoryBytes(t, f.repo.dir)
	o, err := f.observe()
	if err != nil || !o.Ready {
		t.Fatalf("ready profile rejected: %v %#v", err, o.Findings)
	}
	if o.ApplicationAcceptance != "not_established" || o.ObservedRevision != f.repo.head || o.RepositoryURLDigest != spec.Hash([]byte(f.contract.RepositoryURL)) || o.ManifestDigest != spec.Hash(f.manifest) || o.TargetID != f.e.Site.Spec.ClusterID {
		t.Fatalf("lost observation bindings: %#v", o)
	}
	if o.ReconciledAt != f.application.Object["status"].(map[string]any)["reconciledAt"] || o.OperationStartedAt == o.ObservedAt || o.OperationFinishedAt == o.ObservedAt {
		t.Fatal("original controller timestamps were replaced")
	}
	if len(o.Resources) != 3 {
		t.Fatalf("missing reviewed resource facts: %#v", o.Resources)
	}
	for _, r := range o.Resources {
		if !r.DesiredFieldsMatch || !r.OwnershipMatch || !r.TrackingMatch || !r.Healthy || r.UID == "" || r.ResourceVersion == "" {
			t.Fatalf("missing live evidence: %#v", r)
		}
	}
	body, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, withheld := range []string{"CONFIGMAP-SENSITIVE-SENTINEL", f.contract.RepositoryURL} {
		if strings.Contains(string(body), withheld) {
			t.Fatal("observation exposed object values or source URL")
		}
	}
	f.assertReadOnly(t)
	if !reflect.DeepEqual(before, repositoryBytes(t, f.repo.dir)) {
		t.Fatal("observation changed local Git repository")
	}
}

func TestObserveGitOpsProfileBindsResolvedSitePathsAndSelectedState(t *testing.T) {
	f := newProfileFixture(t)
	raw := f.e.Site
	raw.Spec.Kubeconfig, raw.Spec.TrustPolicy, raw.Spec.StateDir = "target.kubeconfig", "trust.json", ""
	f.e.Site.Spec.Kubeconfig = filepath.Join(filepath.Dir(f.sitePath), raw.Spec.Kubeconfig)
	body, err := spec.Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.sitePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	observed, err := f.observe()
	if err != nil || !observed.Ready {
		t.Fatalf("legitimate Site path resolution/default state was rejected: %v %#v", err, observed.Findings)
	}
	if observed.SourceSiteDigest != spec.Hash(body) {
		t.Fatal("raw Site source identity was lost")
	}
}

func TestObserveGitOpsProfileBlocksActiveHelmWithoutReadingValues(t *testing.T) {
	f := newProfileFixture(t)
	base := f.e.HelmRunner
	valuesRead := false
	f.e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "history" {
			return []byte(`[{"revision":1,"status":"deployed","app_version":"1.0.0"}]`), nil
		}
		if args[0] == "get" {
			valuesRead = true
			return []byte(`{}`), nil
		}
		return base(ctx, args...)
	}
	f.denied(t, "HELM_OWNER")
	if valuesRead {
		t.Fatal("active Helm values were read before rejecting competing ownership")
	}
}

func TestObserveGitOpsProfileFrozenRenderNeverReadsAppearingHelmValues(t *testing.T) {
	f := newProfileFixture(t)
	base := f.e.HelmRunner
	historyReads, valuesReads := 0, 0
	f.e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "history" {
			historyReads++
			if historyReads == 1 {
				return nil, errors.New("release: not found")
			}
			return []byte(`[{"revision":1,"status":"deployed","app_version":"1.0.0"}]`), nil
		}
		if args[0] == "get" {
			valuesReads++
			return []byte(`{}`), nil
		}
		return base(ctx, args...)
	}
	f.denied(t, "HELM_CHANGED")
	if historyReads != 2 || valuesReads != 0 {
		t.Fatalf("frozen rendering reopened active release values: history=%d values=%d", historyReads, valuesReads)
	}
}

func TestObserveGitOpsProfileOriginalTimesMustRemainFreshThroughFinalReads(t *testing.T) {
	f := newProfileFixture(t)
	f.contract.MaxAgeSeconds = 2
	var captured *unstructured.Unstructured
	f.client.PrependReactor("get", "applications", func(ktesting.Action) (bool, runtime.Object, error) {
		if captured == nil {
			captured = f.application.DeepCopy()
			for i, field := range []string{"startedAt", "finishedAt"} {
				profileSet(t, captured, time.Now().Add(time.Duration(-100+i*20)*time.Millisecond).UTC().Format(time.RFC3339Nano), "status", "operationState", field)
			}
			profileSet(t, captured, time.Now().Add(-50*time.Millisecond).UTC().Format(time.RFC3339Nano), "status", "reconciledAt")
		}
		return true, captured.DeepCopy(), nil
	})
	namespaceReads := 0
	f.kube.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
		namespaceReads++
		if namespaceReads == 2 {
			time.Sleep(3 * time.Second)
		}
		return true, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test", UID: "namespace-uid"}}, nil
	})
	f.denied(t, "STALE")
}

func TestObserveGitOpsProfileMissingOrDeniedFacts(t *testing.T) {
	for _, resource := range []string{"applications", "deployments", "services", "configmaps", "namespaces"} {
		for _, denied := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/denied=%v", resource, denied), func(t *testing.T) {
				f := newProfileFixture(t)
				reactor := func(a ktesting.Action) (bool, runtime.Object, error) {
					name := a.(ktesting.GetAction).GetName()
					gr := a.GetResource().GroupResource()
					if denied {
						return true, nil, apierrors.NewForbidden(gr, name, errors.New("RAW-API-SENSITIVE-SENTINEL"))
					}
					return true, nil, apierrors.NewNotFound(gr, name)
				}
				code := "RESOURCE_UNAVAILABLE"
				if resource == "namespaces" {
					f.kube.PrependReactor("get", resource, reactor)
					code = "TARGET_UNAVAILABLE"
				} else {
					f.client.PrependReactor("get", resource, reactor)
				}
				if resource == "applications" {
					code = "CONTROLLER_UNAVAILABLE"
				}
				f.denied(t, code)
			})
		}
	}
}

func TestObserveGitOpsProfileChangingFacts(t *testing.T) {
	for _, change := range []string{"application-uid", "application-generation", "application-resource-version", "application-spec-without-version-change", "application-denied-on-reread", "site-source", "site-in-memory", "policy-source", "policy-source-bytes-only", "source-file", "namespace-uid", "server"} {
		t.Run(change, func(t *testing.T) {
			f := newProfileFixture(t)
			code := "CONTROLLER_CHANGED"
			switch change {
			case "site-source", "site-in-memory", "policy-source", "policy-source-bytes-only":
				code = "BINDINGS_CHANGED"
			case "source-file":
				code = "SOURCE_CHANGED"
			case "namespace-uid", "server":
				code = "TARGET_CHANGED"
			}
			f.client.PrependReactor("get", "deployments", func(a ktesting.Action) (bool, runtime.Object, error) {
				switch change {
				case "site-source":
					body, err := os.ReadFile(f.sitePath)
					if err != nil {
						t.Fatal(err)
					}
					mustWriteProposalFile(t, f.sitePath, append(body, '\n'))
				case "site-in-memory":
					f.e.Site.Spec.Namespace = "other"
				case "policy-source":
					p := f.policy
					p.Spec.Epoch++
					body, err := spec.Canonical(p)
					if err != nil {
						t.Fatal(err)
					}
					mustWriteProposalFile(t, f.e.Site.Spec.TrustPolicy, body)
				case "policy-source-bytes-only":
					body, err := os.ReadFile(f.e.Site.Spec.TrustPolicy)
					if err != nil {
						t.Fatal(err)
					}
					mustWriteProposalFile(t, f.e.Site.Spec.TrustPolicy, append(body, '\n'))
				case "source-file":
					mustWriteProposalFile(t, filepath.Join(f.repo.dir, "application.yaml"), []byte("unreviewed: true\n"))
				case "namespace-uid":
					f.kube.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
						return true, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test", UID: "other-uid"}}, nil
					})
				case "server":
					f.e.Kube.Config.Host = "https://other.invalid"
				}
				return false, nil, nil
			})
			reads := 0
			f.client.PrependReactor("get", "applications", func(a ktesting.Action) (bool, runtime.Object, error) {
				reads++
				if reads != 2 {
					return false, nil, nil
				}
				after := f.application.DeepCopy()
				switch change {
				case "application-uid":
					after.SetUID("other-uid")
				case "application-generation":
					after.SetGeneration(after.GetGeneration() + 1)
				case "application-resource-version":
					after.SetResourceVersion("13")
				case "application-spec-without-version-change":
					profileSet(t, after, "other", "spec", "destination", "namespace")
				case "application-denied-on-reread":
					return true, nil, errors.New("RAW-API-SENSITIVE-SENTINEL")
				}
				return true, after, nil
			})
			f.denied(t, code)
		})
	}
}

func TestObserveGitOpsProfileInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   int
		change func(*profileFixture)
	}{
		{"wrong-kind", 2, func(f *profileFixture) { f.contract.Kind = "Other" }},
		{"unsupported-profile", 2, func(f *profileFixture) { f.contract.Profile = "flux-v1" }},
		{"missing-controller-namespace", 2, func(f *profileFixture) { f.contract.Namespace = "" }},
		{"missing-controller-name", 2, func(f *profileFixture) { f.contract.Name = "" }},
		{"missing-controller-uid", 2, func(f *profileFixture) { f.contract.UID = "" }},
		{"missing-local-repository", 2, func(f *profileFixture) { f.contract.Repository = "" }},
		{"credential-url", 2, func(f *profileFixture) {
			f.contract.RepositoryURL = "https://user:PRODUCER-CREDENTIAL-SENTINEL@git.example.invalid/private.git"
		}},
		{"url-query", 2, func(f *profileFixture) { f.contract.RepositoryURL += "?token=PRODUCER-CREDENTIAL-SENTINEL" }},
		{"url-fragment", 2, func(f *profileFixture) { f.contract.RepositoryURL += "#PRODUCER-CREDENTIAL-SENTINEL" }},
		{"ssh-url", 2, func(f *profileFixture) { f.contract.RepositoryURL = "ssh://git.example.invalid/source.git" }},
		{"moving-revision", 2, func(f *profileFixture) { f.contract.AcceptedRevision = "main" }},
		{"short-revision", 2, func(f *profileFixture) { f.contract.AcceptedRevision = f.repo.head[:12] }},
		{"upper-case-revision", 2, func(f *profileFixture) { f.contract.AcceptedRevision = strings.Repeat("A", 40) }},
		{"bad-manifest-digest", 2, func(f *profileFixture) { f.contract.ManifestDigest = strings.Repeat("a", 64) }},
		{"wrong-manifest-digest", 2, func(f *profileFixture) { f.contract.ManifestDigest = "sha256:" + strings.Repeat("a", 64) }},
		{"empty-manifest", 2, func(f *profileFixture) { f.manifest = nil }},
		{"missing-notBefore", 2, func(f *profileFixture) { f.contract.NotBefore = "" }},
		{"future-notBefore", 2, func(f *profileFixture) {
			f.contract.NotBefore = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
		}},
		{"zero-maxAge", 2, func(f *profileFixture) { f.contract.MaxAgeSeconds = 0 }},
		{"unbounded-maxAge", 2, func(f *profileFixture) { f.contract.MaxAgeSeconds = 86401 }},
		{"invalid-reversion", 2, func(f *profileFixture) {
			f.contract.Reversion = &spec.GitOpsProfileReversion{PreviousRevision: "HEAD", RestoredRevision: f.repo.head}
		}},
		{"flux-release-owner", 10, func(f *profileFixture) { f.v.Index.Lock.Release.Spec.Deployment.GitOps.Owner = "flux" }},
		{"unsigned-path-escape", 10, func(f *profileFixture) { f.v.Index.Lock.Release.Spec.Deployment.GitOps.Path = "../application.yaml" }},
		{"site-profile-mismatch", 10, func(f *profileFixture) { f.e.Site.Spec.Profile = "other" }},
		{"site-capability-denied", 16, func(f *profileFixture) { f.e.Site.Spec.AllowedActions = nil }},
		{"policy-capability-denied", 16, func(f *profileFixture) { f.policy.Spec.AllowedActions = nil }},
		{"state-in-source-repository", 2, func(f *profileFixture) { f.e.StateDir = f.repo.dir }},
		{"render-differs-from-reviewed", 2, func(f *profileFixture) {
			f.manifest = bytes.ReplaceAll(f.manifest, []byte("CONFIGMAP-SENSITIVE-SENTINEL"), []byte("UNREVIEWED-CONFIG-SENTINEL"))
			f.contract.ManifestDigest = spec.Hash(f.manifest)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProfileFixture(t)
			tc.change(f)
			o, err := f.observe()
			var typed *spec.Error
			if !errors.As(err, &typed) || spec.ExitCode(err) != tc.code || o.Ready {
				t.Fatalf("invalid input did not fail with typed error %d: %v %#v", tc.code, err, o.Findings)
			}
			f.assertReadOnly(t)
			f.assertWithheld(t, o, err)
		})
	}
	f := newProfileFixture(t)
	body, err := spec.Canonical(f.contract)
	if err != nil {
		t.Fatal(err)
	}
	var parsed spec.GitOpsProfileContract
	if err = spec.Decode(body, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, injected := range []string{`"executable":"unreviewed",`, `"fieldPaths":["status.unreviewed"],`, `"dsl":"unreviewed",`} {
		input := append([]byte("{"+injected), body[1:]...)
		if spec.Decode(input, &parsed) == nil {
			t.Fatal("external JSON accepted a caller-defined adapter")
		}
	}
}

func TestObserveGitOpsProfileSupportedBindings(t *testing.T) {
	for _, variant := range []string{"sha256", "installation-id", "nested-file", "granular-managed-fields", "safe-operation-options", "http-url", "nonworkload-health", "withheld-status-messages"} {
		t.Run(variant, func(t *testing.T) {
			var options []string
			if variant == "sha256" {
				options = []string{"--object-format=sha256"}
			}
			f := newProfileFixture(t, options...)
			switch variant {
			case "installation-id":
				f.contract.InstallationID = "installation-one"
				for _, live := range f.live {
					profileSet(t, live, f.contract.InstallationID, "metadata", "annotations", "argocd.argoproj.io/installation-id")
					entries, _, _ := unstructured.NestedSlice(live.Object, "metadata", "managedFields")
					entries[0].(map[string]any)["fieldsV1"].(map[string]any)["f:metadata"].(map[string]any)["f:annotations"].(map[string]any)["f:argocd.argoproj.io/installation-id"] = map[string]any{}
					profileSet(t, live, entries, "metadata", "managedFields")
				}
			case "nested-file":
				if err := os.Mkdir(filepath.Join(f.repo.dir, "manifests"), 0700); err != nil {
					t.Fatal(err)
				}
				f.repo.command(nil, "mv", "application.yaml", "manifests/desired.yml")
				f.repo.command(nil, "commit", "-m", "Fixture nested signed file")
				f.accepted(t, strings.TrimSpace(string(f.repo.command(nil, "rev-parse", "HEAD"))))
				f.v.Index.Lock.Release.Spec.Deployment.GitOps.Path = "manifests/desired.yml"
				for _, fields := range [][]string{{"spec", "source"}, {"status", "sync", "comparedTo", "source"}, {"status", "operationState", "syncResult", "source"}} {
					profileSet(t, f.application, "manifests", append(fields, "path")...)
					profileSet(t, f.application, "desired.yml", append(fields, "directory", "include")...)
				}
			case "granular-managed-fields":
				entries, _, _ := unstructured.NestedSlice(f.live[0].Object, "metadata", "managedFields")
				fields := entries[0].(map[string]any)["fieldsV1"].(map[string]any)
				fields["f:spec"] = map[string]any{"f:replicas": map[string]any{}, "f:selector": map[string]any{}, "f:template": map[string]any{"f:metadata": map[string]any{"f:labels": map[string]any{"f:app": map[string]any{}}}, "f:spec": map[string]any{"f:containers": map[string]any{`k:{"name":"app"}`: map[string]any{".": map[string]any{}, "f:name": map[string]any{}, "f:image": map[string]any{}}}}}}
				entries = append(entries, map[string]any{"manager": "kube-controller-manager", "operation": "Update", "apiVersion": "apps/v1", "subresource": "status", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:status": map[string]any{}}})
				profileSet(t, f.live[0], "1", "metadata", "annotations", "deployment.kubernetes.io/revision")
				entries = append(entries, map[string]any{"manager": "kube-controller-manager", "operation": "Update", "apiVersion": "apps/v1", "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:metadata": map[string]any{"f:annotations": map[string]any{".": map[string]any{}, "f:deployment.kubernetes.io/revision": map[string]any{}}}}})
				profileSet(t, f.live[0], entries, "metadata", "managedFields")
			case "safe-operation-options":
				profileSet(t, f.application, []any{"ServerSideApply=true", "FailOnSharedResource=true", "DisableClientSideApplyMigration=true"}, "status", "operationState", "operation", "sync", "syncOptions")
				profileSet(t, f.application, map[string]any{"apply": map[string]any{"force": false}}, "status", "operationState", "operation", "sync", "syncStrategy")
			case "http-url":
				f.contract.RepositoryURL = "http://git.example.invalid/source.git"
				for _, fields := range [][]string{{"spec", "source", "repoURL"}, {"status", "sync", "comparedTo", "source", "repoURL"}, {"status", "operationState", "syncResult", "source", "repoURL"}} {
					profileSet(t, f.application, f.contract.RepositoryURL, fields...)
				}
			case "nonworkload-health":
				resources, _, _ := unstructured.NestedSlice(f.application.Object, "status", "resources")
				for _, value := range resources {
					value.(map[string]any)["health"] = map[string]any{"status": "Healthy"}
				}
				profileSet(t, f.application, resources, "status", "resources")
			case "withheld-status-messages":
				profileSet(t, f.application, "STATUS-SENSITIVE-SENTINEL", "status", "health", "message")
				profileSet(t, f.application, "STATUS-SENSITIVE-SENTINEL", "status", "operationState", "message")
			}
			f.seed(t)
			o, err := f.observe()
			if err != nil || !o.Ready || o.ObservedRevision != f.repo.head || o.RepositoryURLDigest != spec.Hash([]byte(f.contract.RepositoryURL)) {
				t.Fatalf("supported binding rejected: %v %#v", err, o.Findings)
			}
			f.assertWithheld(t, o, err)
			f.assertReadOnly(t)
		})
	}
}

func TestObserveGitOpsProfileUnavailableBindings(t *testing.T) {
	for _, change := range []string{"missing-site", "different-site", "missing-policy", "different-policy", "missing-namespace-uid", "wrong-namespace-pin", "wrong-cluster-pin", "nil-kubernetes", "missing-local-repository", "fifo-site", "fifo-policy"} {
		t.Run(change, func(t *testing.T) {
			f := newProfileFixture(t)
			code := "BINDINGS_UNAVAILABLE"
			switch change {
			case "missing-site":
				if err := os.Remove(f.sitePath); err != nil {
					t.Fatal(err)
				}
			case "different-site":
				site := f.e.Site
				site.Spec.Profile = "other"
				body, err := spec.Canonical(site)
				if err != nil {
					t.Fatal(err)
				}
				mustWriteProposalFile(t, f.sitePath, body)
			case "missing-policy":
				if err := os.Remove(f.e.Site.Spec.TrustPolicy); err != nil {
					t.Fatal(err)
				}
			case "different-policy":
				policy := f.policy
				policy.Spec.Epoch++
				body, err := spec.Canonical(policy)
				if err != nil {
					t.Fatal(err)
				}
				mustWriteProposalFile(t, f.e.Site.Spec.TrustPolicy, body)
			case "missing-namespace-uid":
				f.kube.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test"}}, nil
				})
				code = "TARGET_UNAVAILABLE"
			case "wrong-namespace-pin", "wrong-cluster-pin":
				if change == "wrong-namespace-pin" {
					f.e.Site.Spec.NamespaceUID = "other"
				} else {
					f.e.Site.Spec.ClusterID = "sha256:" + strings.Repeat("0", 64)
				}
				body, err := spec.Canonical(f.e.Site)
				if err != nil {
					t.Fatal(err)
				}
				mustWriteProposalFile(t, f.sitePath, body)
				code = "TARGET_UNAVAILABLE"
			case "nil-kubernetes":
				f.e.Kube = nil
				code = "TARGET_UNAVAILABLE"
			case "missing-local-repository":
				f.contract.Repository = filepath.Join(f.repo.dir, "missing")
				code = "SOURCE_UNAVAILABLE"
			case "fifo-site", "fifo-policy":
				file := f.sitePath
				if change == "fifo-policy" {
					file = f.e.Site.Spec.TrustPolicy
				}
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(file, 0600); err != nil {
					t.Fatal(err)
				}
			}
			f.denied(t, code)
		})
	}
}

func TestObserveGitOpsProfileRenderingNeverDiscoversNodes(t *testing.T) {
	for _, nodeName := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit-node=%v", nodeName), func(t *testing.T) {
			f := newProfileFixture(t)
			f.v.Index.Lock.Release.Spec.AIProfile = spec.AIProfile{GPUCount: 1, RuntimeAsset: "runner"}
			f.e.Site.Spec.HardwareEvidence = filepath.Join(f.e.StateDir, "hardware.json")
			if err := spec.Write(f.e.Site.Spec.HardwareEvidence, HardwareEvidence{Header: spec.NewHeader("HardwareEvidence"), NodeName: "gpu-node", GPUs: []GPUFact{{UUID: "GPU-fixture"}}}); err != nil {
				t.Fatal(err)
			}
			site, err := spec.Canonical(f.e.Site)
			if err != nil {
				t.Fatal(err)
			}
			mustWriteProposalFile(t, f.sitePath, site)
			objects, err := PermissionObjects(f.manifest)
			if err != nil {
				t.Fatal(err)
			}
			pod := objects[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
			pod["containers"].([]any)[0].(map[string]any)["resources"] = map[string]any{"limits": map[string]any{"nvidia.com/gpu": "1"}}
			if nodeName {
				pod["nodeName"] = "gpu-node"
			} else {
				pod["nodeSelector"] = map[string]any{"gpu": "true"}
			}
			f.reviewObjects(t, objects)
			f.kube.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
				t.Fatal("rendering attempted node discovery")
				return true, nil, nil
			})
			_, err = f.observe()
			if spec.ExitCode(err) != 10 {
				t.Fatalf("hardware scope was not rejected: %v", err)
			}
			f.assertReadOnly(t)
		})
	}
}

func TestObserveGitOpsRawArgoCompatibility(t *testing.T) {
	f := newProfileFixture(t)
	profileSet(t, f.application, "main", "status", "sync", "revision")
	delete(f.application.Object, "spec")
	f.seed(t)
	o, err := f.e.ObserveGitOps(context.Background(), "argocd", f.contract.Namespace, f.contract.Name, "main", f.policy)
	if err != nil || !o.ControllerReady || o.ObservedRevision != "main" || o.ApplicationAcceptance != "not_tested" {
		t.Fatalf("raw Argo status compatibility changed: %v %#v", err, o)
	}
	f.assertReadOnly(t)
}
