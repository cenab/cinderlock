package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"
)

func admissionServer(t *testing.T, handler http.HandlerFunc) (*Engine, spec.TrustPolicy) {
	t.Helper()
	e, _, policy := fixture(t)
	e.Site.Spec.AdmissionDryRun = true
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "admission-dry-run")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "admission-dry-run")
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := dynamic.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	e.DynamicClient = client
	return e, policy
}

func TestAdmissionUsesOnlyNonpersistentRequests(t *testing.T) {
	reads, writes := 0, 0
	e, policy := admissionServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			reads++
			w.WriteHeader(404)
			w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`))
			return
		}
		writes++
		if r.Method != "POST" || r.URL.Query().Get("dryRun") != "All" || r.URL.Path != "/api/v1/namespaces/test/configmaps" {
			t.Errorf("persistent or unbounded request: %s %s", r.Method, r.URL)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		metadata := body["metadata"].(map[string]any)
		if metadata["namespace"] != "test" || metadata["annotations"].(map[string]any)["meta.helm.sh/release-name"] != "app" {
			t.Fatal("Helm execution metadata missing", metadata)
		}
		json.NewEncoder(w).Encode(body)
	})
	objects := []map[string]any{{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "settings"}, "data": map[string]any{"setting": "value"}}}
	findings := e.AdmissionFindings(context.Background(), spec.Plan{Operations: []spec.Operation{{ID: "deploy", Type: "helm"}}}, objects, policy)
	if blockersForTest(findings) || reads != 1 || writes != 1 {
		t.Fatal(findings, reads, writes)
	}
}

func blockersForTest(findings []spec.Finding) bool {
	for _, f := range findings {
		if f.Severity == "blocker" {
			return true
		}
	}
	return false
}

func TestAdmissionCancellationCannotAcceptIncompleteInventory(t *testing.T) {
	e, _, policy := fixture(t)
	e.Site.Spec.AdmissionDryRun = true
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "admission-dry-run")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "admission-dry-run")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	creates := 0
	client.PrependReactor("create", "configmaps", func(action clienttesting.Action) (bool, runtime.Object, error) {
		creates++
		cancel()
		return true, action.(clienttesting.CreateAction).GetObject(), nil
	})
	e.DynamicClient = client
	objects := []map[string]any{
		{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "first"}},
		{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "second"}},
	}
	p := spec.Plan{Executable: true, Operations: []spec.Operation{{ID: "deploy", Type: "helm"}}}
	e.addAdmissionFindings(ctx, &p, objects, policy)
	if p.Executable || !blockersForTest(p.Findings) || creates != 1 {
		t.Fatalf("incomplete admission accepted: executable=%v creates=%d findings=%+v", p.Executable, creates, p.Findings)
	}
}

func TestAdmissionRedactsRejectedValuesAndRequiresCapabilities(t *testing.T) {
	requests := 0
	e, policy := admissionServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			w.WriteHeader(404)
			w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`))
			return
		}
		if r.URL.Query().Get("dryRun") != "All" {
			t.Fatal("non-dry-run write")
		}
		w.WriteHeader(422)
		w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Invalid","message":"PRIVATE-SERVER-VALUE","code":422}`))
	})
	objects := []map[string]any{{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "settings"}}}
	p := spec.Plan{Operations: []spec.Operation{{ID: "deploy", Type: "helm"}}}
	findings := e.AdmissionFindings(context.Background(), p, objects, policy)
	b, _ := json.Marshal(findings)
	if !blockersForTest(findings) || strings.Contains(string(b), "PRIVATE-SERVER-VALUE") {
		t.Fatal(string(b))
	}
	requests = 0
	e.Site.Spec.AllowedActions = nil
	if !blockersForTest(e.AdmissionFindings(context.Background(), p, objects, policy)) || requests != 0 {
		t.Fatal("unadmitted preflight contacted API")
	}
	e.Site.Spec.AdmissionDryRun = false
	if blockersForTest(e.AdmissionFindings(context.Background(), p, objects, policy)) || requests != 0 {
		t.Fatal("disabled preflight contacted API")
	}
}

func TestAdmissionThreeWayPatchPreservesAssignedServiceFields(t *testing.T) {
	var original, desired, current map[string]any
	json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"app"},"spec":{"ports":[{"port":80,"targetPort":8080}],"selector":{"app":"app"}}}`), &original)
	json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"app"},"spec":{"ports":[{"port":80,"targetPort":9090}],"selector":{"app":"app"}}}`), &desired)
	json.Unmarshal([]byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"app","resourceVersion":"123"},"spec":{"clusterIP":"10.0.0.5","ports":[{"port":80,"targetPort":8080,"protocol":"TCP"}],"selector":{"app":"app"}}}`), &current)
	patch, err := admissionPatch(original, desired, current)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(current)
	result, err := strategicpatch.StrategicMergePatch(before, patch, &corev1.Service{})
	if err != nil {
		t.Fatal(err)
	}
	var service corev1.Service
	if err = json.Unmarshal(result, &service); err != nil {
		t.Fatal(err)
	}
	if service.Spec.ClusterIP != "10.0.0.5" || service.Spec.Ports[0].TargetPort.IntValue() != 9090 {
		t.Fatal(string(result))
	}
}

func TestAdmissionRefusesCrossNamespaceAndMalformedMetadata(t *testing.T) {
	calls := 0
	e, policy := admissionServer(t, func(w http.ResponseWriter, r *http.Request) { calls++; http.Error(w, "unexpected", 500) })
	p := spec.Plan{Operations: []spec.Operation{{ID: "deploy", Type: "helm"}}}
	for _, object := range []map[string]any{
		{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "config", "namespace": "other"}},
		{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "config", "labels": map[string]any{"invalid": 1}}},
		{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "another"}},
	} {
		if !blockersForTest(e.AdmissionFindings(context.Background(), p, []map[string]any{object}, policy)) {
			t.Fatal("invalid scope accepted", object)
		}
	}
	if calls != 0 {
		t.Fatal("invalid scope contacted API", calls)
	}
}
