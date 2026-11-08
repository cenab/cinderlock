package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	kubetesting "k8s.io/client-go/testing"
)

func permissionServer(t *testing.T, result func(authorizationv1.ResourceAttributes) authorizationv1.SubjectAccessReviewStatus) (*Engine, func() []authorizationv1.ResourceAttributes) {
	t.Helper()
	observed := []authorizationv1.ResourceAttributes{}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			t.Errorf("unexpected workload request %s %s", r.Method, r.URL)
			http.Error(w, "unexpected workload request", http.StatusForbidden)
			return
		}
		var request authorizationv1.SelfSubjectAccessReview
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if request.Spec.ResourceAttributes == nil || request.Spec.NonResourceAttributes != nil {
			t.Error("expected exact resource review")
			http.Error(w, "invalid review", http.StatusBadRequest)
			return
		}
		a := *request.Spec.ResourceAttributes
		mu.Lock()
		observed = append(observed, a)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(authorizationv1.SelfSubjectAccessReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: request.Spec, Status: result(a)})
	}))
	t.Cleanup(server.Close)
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: 1000, Burst: 1000, ContentConfig: rest.ContentConfig{ContentType: "application/json", AcceptContentTypes: "application/json"}})
	if err != nil {
		t.Fatal(err)
	}
	e := NewWithClient(spec.Site{Spec: spec.SiteSpec{Namespace: "tenant-a", ReleaseName: "document-qa"}}, nil, client)
	return e, func() []authorizationv1.ResourceAttributes {
		mu.Lock()
		defer mu.Unlock()
		return append([]authorizationv1.ResourceAttributes{}, observed...)
	}
}

func TestPermissionPreflightBlocksDeniedJobWithoutWorkloadWrites(t *testing.T) {
	e, requests := permissionServer(t, func(a authorizationv1.ResourceAttributes) authorizationv1.SubjectAccessReviewStatus {
		if a.Group == "batch" && a.Resource == "jobs" && a.Verb == "create" {
			return authorizationv1.SubjectAccessReviewStatus{Denied: true, Reason: "PRIVATE-SERVER-DETAIL"}
		}
		return authorizationv1.SubjectAccessReviewStatus{Allowed: true}
	})
	p := spec.Plan{Operations: []spec.Operation{{ID: "migration", Type: "migrate"}}, Checks: []spec.Check{{ID: "acceptance", Type: "job"}}}
	findings := e.PermissionFindings(context.Background(), p, nil)
	found := false
	for _, finding := range findings {
		if finding.Code == "PERMISSION_DENIED" && strings.Contains(finding.Message, "create jobs.batch") {
			found = finding.Severity == "blocker"
		}
		if strings.Contains(finding.Message, "PRIVATE-SERVER-DETAIL") {
			t.Fatal("authorization diagnostic leaked")
		}
	}
	if !found {
		t.Fatalf("denied execution permission did not block: %+v", findings)
	}
	if len(requests()) == 0 {
		t.Fatal("authorization API was not queried")
	}
	for _, a := range requests() {
		if a.Resource == "namespaces" {
			if a.Namespace != "" || a.Name != "tenant-a" || a.Verb != "get" {
				t.Fatalf("namespace identity check broadened: %+v", a)
			}
			continue
		}
		if a.Namespace != "tenant-a" || a.Resource == "nodes" || a.Verb == "*" || a.Resource == "*" {
			t.Fatalf("CPU job permission escaped target scope: %+v", a)
		}
		if a.Resource == "deployments" && a.Verb != "list" {
			t.Fatalf("migration requested unrelated Deployment mutation: %+v", a)
		}
	}
}

func TestPermissionPreflightBlocksUnavailableAPI(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(kubetesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("PRIVATE-TRANSPORT-DETAIL")
	})
	e := NewWithClient(spec.Site{Spec: spec.SiteSpec{Namespace: "tenant-a", ReleaseName: "qa"}}, nil, client)
	findings := e.PermissionFindings(context.Background(), spec.Plan{Operations: []spec.Operation{{ID: "import", Type: "import"}}}, nil)
	blocked := false
	for _, finding := range findings {
		blocked = blocked || finding.Code == "PERMISSION_UNAVAILABLE" && finding.Severity == "blocker"
		if strings.Contains(finding.Message, "PRIVATE-TRANSPORT-DETAIL") {
			t.Fatal("raw transport detail leaked")
		}
	}
	if !blocked {
		t.Fatalf("unavailable API did not block: %+v", findings)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "create" || action.GetResource().Resource != "selfsubjectaccessreviews" {
			t.Fatalf("unexpected workload API action: %+v", action)
		}
	}
}

func TestPermissionPreflightRequiresConclusiveAllowance(t *testing.T) {
	for _, status := range []authorizationv1.SubjectAccessReviewStatus{{}, {Allowed: true, EvaluationError: "incomplete authorizer"}, {Allowed: true, Denied: true}} {
		e, _ := permissionServer(t, func(authorizationv1.ResourceAttributes) authorizationv1.SubjectAccessReviewStatus { return status })
		findings := e.PermissionFindings(context.Background(), spec.Plan{Operations: []spec.Operation{{ID: "import", Type: "import"}}}, nil)
		blocked := false
		for _, finding := range findings {
			blocked = blocked || finding.Severity == "blocker"
		}
		if !blocked {
			t.Fatalf("inconclusive review allowed execution: %+v", status)
		}
	}
	e, _ := permissionServer(t, func(authorizationv1.ResourceAttributes) authorizationv1.SubjectAccessReviewStatus {
		return authorizationv1.SubjectAccessReviewStatus{Allowed: true}
	})
	for _, finding := range e.PermissionFindings(context.Background(), spec.Plan{Operations: []spec.Operation{{ID: "import", Type: "import"}}}, nil) {
		if finding.Severity == "blocker" {
			t.Fatalf("positive control blocked: %+v", finding)
		}
	}
}

func TestPermissionPreflightCoversRemovedObjectsAndProtectsRetainedData(t *testing.T) {
	e, requests := permissionServer(t, func(a authorizationv1.ResourceAttributes) authorizationv1.SubjectAccessReviewStatus {
		if a.Resource == "services" && a.Name == "obsolete" && a.Verb == "delete" {
			return authorizationv1.SubjectAccessReviewStatus{Denied: true}
		}
		return authorizationv1.SubjectAccessReviewStatus{Allowed: true}
	})
	e.HelmRunner = func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) != 3 || args[0] != "get" || args[1] != "manifest" || args[2] != "document-qa" {
			t.Fatalf("unexpected Helm request: %v", args)
		}
		return []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: document-qa\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: obsolete\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: retained\n  annotations:\n    helm.sh/resource-policy: keep\n"), nil
	}
	objects := []map[string]any{{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "document-qa", "namespace": "tenant-a"}}}
	findings := e.PermissionFindings(context.Background(), spec.Plan{SourceVersion: "1.0.0", Operations: []spec.Operation{{ID: "deploy", Type: "helm"}}}, objects)
	blocked := false
	for _, finding := range findings {
		blocked = blocked || finding.Code == "PERMISSION_DENIED" && strings.Contains(finding.Message, "delete services/obsolete")
	}
	if !blocked {
		t.Fatalf("removed-object permission not checked: %+v", findings)
	}
	patch := false
	for _, a := range requests() {
		if a.Namespace != "" && a.Namespace != "tenant-a" {
			t.Fatalf("escaped namespace: %+v", a)
		}
		if a.Verb == "delete" && (a.Name == "retained" || a.Name == "document-qa") {
			t.Fatalf("unnecessary resource destruction permission: %+v", a)
		}
		patch = patch || a.Resource == "deployments" && a.Name == "document-qa" && a.Verb == "patch"
	}
	if !patch {
		t.Fatal("current Deployment patch permission not checked")
	}
}

func TestPermissionPreflightRejectsUnboundedObjectScope(t *testing.T) {
	e, requests := permissionServer(t, func(authorizationv1.ResourceAttributes) authorizationv1.SubjectAccessReviewStatus {
		return authorizationv1.SubjectAccessReviewStatus{Allowed: true}
	})
	for _, object := range []map[string]any{
		{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "api", "namespace": "another-tenant"}},
		{"apiVersion": "unknown.invalid/v1", "kind": "Service", "metadata": map[string]any{"name": "api"}},
		{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": map[string]any{"name": "admin"}},
		{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{}},
	} {
		findings := e.PermissionFindings(context.Background(), spec.Plan{Operations: []spec.Operation{{ID: "deploy", Type: "helm"}}}, []map[string]any{object})
		if len(findings) != 1 || findings[0].Code != "PERMISSION_SCOPE_UNAVAILABLE" || findings[0].Severity != "blocker" {
			t.Fatalf("unsafe scope was not rejected: %+v", findings)
		}
	}
	if len(requests()) != 0 {
		t.Fatalf("invalid scope reached authorization API: %+v", requests())
	}
}

func TestNativeSeedPermissionIncludesAttachOnlyForStream(t *testing.T) {
	e, _, _ := fixture(t)
	p := spec.Plan{Operations: []spec.Operation{{ID: "models", Type: "seed", PVC: "models"}}}
	for _, native := range []bool{true, false} {
		if !native {
			p.Operations[0].Command = []string{"copy-model"}
		}
		requirements, err := e.permissionRequirements(p, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		attach := false
		for _, r := range requirements {
			if r.Resource == "pods" && r.Subresource == "attach" {
				attach = true
				if r.Verb != "create" || r.Namespace != "test" {
					t.Fatal("incorrect attach scope", r)
				}
			}
			if r.Resource == "pods" && r.Subresource == "exec" {
				t.Fatal("native transfer should not require arbitrary exec", r)
			}
		}
		if attach != native {
			t.Fatalf("attach permission native=%v got=%v", native, attach)
		}
	}
}

func TestPermissionPlanDisclosesStepRequirementsAndIdentities(t *testing.T) {
	e, requests := permissionServer(t, func(a authorizationv1.ResourceAttributes) authorizationv1.SubjectAccessReviewStatus {
		if a.Resource == "jobs" && a.Verb == "create" {
			return authorizationv1.SubjectAccessReviewStatus{Denied: true}
		}
		return authorizationv1.SubjectAccessReviewStatus{Allowed: true}
	})
	e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"token": {Name: "credentials", Key: "token"}}
	p := spec.Plan{Operations: []spec.Operation{{ID: "migration", Type: "migrate"}, {ID: "deploy", Type: "helm"}}, Checks: []spec.Check{{ID: "acceptance", Type: "job", SecretRefs: []string{"token"}}}}
	objects := []map[string]any{{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "app"}, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccountName": "application", "automountServiceAccountToken": true}}}}}
	objects = append(objects,
		map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": map[string]any{"name": "default"}, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{}}}},
		map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "alias"}, "spec": map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccount": "compat"}}}},
	)
	findings := e.PermissionFindings(context.Background(), p, objects)
	for _, want := range []struct{ source, code, value string }{
		{"operation/migration", "PERMISSION_REQUIRED", "create jobs.batch"},
		{"check/acceptance", "PERMISSION_REQUIRED", "create jobs.batch"},
		{"check/acceptance", "PERMISSION_REQUIRED", "get secrets/credentials"},
		{"operation/deploy", "PERMISSION_REQUIRED", "create deployments.apps"},
		{"operation/migration", "CAPABILITY_REQUIRED", "migrate"},
		{"check/acceptance", "CAPABILITY_REQUIRED", "job"},
		{"operation/migration", "SERVICE_ACCOUNT_REQUIRED", "tenant-a/default"},
		{"check/acceptance", "SERVICE_ACCOUNT_REQUIRED", "tenant-a/default"},
		{"operation/deploy", "SERVICE_ACCOUNT_REQUIRED", "tenant-a/application"},
		{"operation/deploy", "SERVICE_ACCOUNT_REQUIRED", "tenant-a/default"},
		{"operation/deploy", "SERVICE_ACCOUNT_REQUIRED", "tenant-a/compat"},
	} {
		found := false
		for _, finding := range findings {
			found = found || finding.Source == want.source && finding.Code == want.code && strings.Contains(finding.Message, want.value)
		}
		if !found {
			t.Fatalf("missing %s %s %s", want.source, want.code, want.value)
		}
	}
	denied := false
	for _, finding := range findings {
		denied = denied || finding.Code == "PERMISSION_DENIED" && finding.Severity == "blocker" && strings.Contains(finding.Message, "create jobs.batch")
	}
	if !denied {
		t.Fatal("step disclosure lost the denial")
	}
	seen := map[authorizationv1.ResourceAttributes]bool{}
	for _, request := range requests() {
		if seen[request] {
			t.Fatalf("same caller permission queried repeatedly: %+v", request)
		}
		seen[request] = true
	}
}
