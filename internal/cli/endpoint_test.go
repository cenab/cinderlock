package cli_test

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestEndpointWorkerUsesExplicitTLSMaterialWithoutDisclosingIt(t *testing.T) {
	const credential = "Bearer synthetic-endpoint-credential"
	const responseBody = "synthetic private response body"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != credential {
			t.Errorf("approved Authorization material was not supplied: %q", got)
		}
		fmt.Fprint(w, responseBody)
	}))
	defer server.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	t.Setenv("CINDERLOCK_ENDPOINT_CA_PEM", ca)
	t.Setenv("CINDERLOCK_ENDPOINT_AUTHORIZATION", credential)
	h := newHarness(t)
	result := h.command("helper", "endpoint-probe", "--url", server.URL, "--expected-status", "200", "--ca", "--authorization")
	if result.err != nil {
		t.Fatalf("fixed endpoint worker could not observe the admitted TLS endpoint: %v stderr=%s", result.err, result.stderr)
	}
	var observation struct {
		Status        int    `json:"status"`
		Response      string `json:"response"`
		Authorization string `json:"authorization"`
	}
	if err := json.Unmarshal(result.result, &observation); err != nil {
		t.Fatal(err)
	}
	if observation.Status != 200 || observation.Response != "observed" || observation.Authorization != "supplied" {
		t.Fatalf("unexpected scoped observation: %s", result.result)
	}
	for _, private := range []string{credential, ca, responseBody} {
		if strings.Contains(string(result.raw)+result.stderr, private) {
			t.Fatal("worker output disclosed request material or response content")
		}
	}
}

func TestEndpointWorkerRejectsPrivateInputsWithoutPrintingThem(t *testing.T) {
	const private = "private-endpoint-input-sentinel"
	for _, args := range [][]string{
		{"--url", "https://user:" + private + "@endpoint.invalid/"},
		{"--url", "https://endpoint.invalid/?token=" + private},
		{"--url", "https://endpoint.invalid/#" + private},
		{"--url", "https://endpoint.invalid/", "--authorization"},
		{"--url", "https://endpoint.invalid/", "--ca"},
		{"--url", "https://endpoint.invalid/", "--authorization=" + private},
		{"--url", "https://endpoint.invalid/", private},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Setenv("CINDERLOCK_ENDPOINT_CA_PEM", "")
			t.Setenv("CINDERLOCK_ENDPOINT_AUTHORIZATION", "")
			h := newHarness(t)
			result := h.command(append([]string{"helper", "endpoint-probe"}, args...)...)
			if spec.ExitCode(result.err) != 2 || strings.Contains(string(result.raw)+result.stderr+result.err.Error(), private) {
				t.Fatalf("worker did not safely reject private input: %v stderr=%s result=%s", result.err, result.stderr, result.raw)
			}
		})
	}
}

func TestEndpointWorkerRejectsExpectedRedirectAndReportsOnlyObservedStatus(t *testing.T) {
	const body = "private-endpoint-response-body"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://must-not-be-contacted.invalid/private-location")
		w.WriteHeader(http.StatusFound)
		fmt.Fprint(w, body)
	}))
	defer server.Close()
	h := newHarness(t)
	result := h.command("helper", "endpoint-probe", "--url", server.URL, "--allow-http", "--expected-status", "302")
	if spec.ExitCode(result.err) != 14 || strings.Contains(string(result.raw)+result.stderr, body) || strings.Contains(string(result.raw)+result.stderr, "must-not-be-contacted") {
		t.Fatalf("redirect became a passing prerequisite or disclosed response data: %v %s", result.err, result.raw)
	}
	var observation struct {
		Status        int    `json:"status"`
		Response      string `json:"response"`
		Authorization string `json:"authorization"`
	}
	if err := json.Unmarshal(result.result, &observation); err != nil {
		t.Fatal(err)
	}
	if observation.Status != 302 || observation.Response != "observed" || observation.Authorization != "not_supplied" {
		t.Fatalf("redirect result lost its limited observation scope: %s", result.result)
	}
}

func TestEndpointAuthorizationCommandDerivesCapabilities(t *testing.T) {
	f := makeArtifactFixture(t)
	h := f.h
	key, public := filepath.Join(h.dir, "approval.key"), filepath.Join(h.dir, "approval.pub")
	h.ok("trust", "keygen", "--private", key, "--public", public)
	policyPath := filepath.Join(h.dir, "endpoint-policy.json")
	h.ok("trust", "propose-update", f.policyPath, "--public", public, "--key-id", "customer", "--role", "approval", "--application", "cli-fixture", "--out", policyPath)
	policy := decode[spec.TrustPolicy](t, read(t, policyPath))
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "endpoint-probe", "endpoint-http")
	encoded, err := spec.Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	write(t, policyPath, encoded)
	site := spec.Site{Header: spec.NewHeader("Site"), Spec: spec.SiteSpec{Kubeconfig: "test-only", Context: "test-only", Namespace: "application", ReleaseName: "application", TrustPolicy: policyPath, Profile: "test", AllowedActions: []string{"job", "endpoint-probe", "endpoint-http"}}}
	site.Metadata.Name = "test"
	sitePath := filepath.Join(h.dir, "endpoint-site.json")
	if err := spec.Write(sitePath, site); err != nil {
		t.Fatal(err)
	}
	plan := spec.Plan{Header: spec.NewHeader("Plan"), SitePath: sitePath, Executable: true, PolicyEpoch: policy.Spec.Epoch, Operations: []spec.Operation{{ID: "deploy", Type: "helm"}}, Snapshot: spec.TargetSnapshot{TargetID: "test-target"}, Checks: []spec.Check{{ID: "route", Type: "endpoint", Required: true, Domain: "readiness", URL: "http://registry.internal/", ExpectedStatus: 200}}}
	plan.Metadata = f.release.Metadata
	plan.PolicyDigest, _ = spec.Digest(policy)
	planPath, authPath := filepath.Join(h.dir, "endpoint-plan.json"), filepath.Join(h.dir, "endpoint-authorization.json")
	if err := spec.Write(planPath, plan); err != nil {
		t.Fatal(err)
	}
	h.ok("run", "authorize", planPath, "--key", key, "--key-id", "customer", "--out", authPath)
	a := decode[spec.Authorization](t, read(t, authPath))
	if !slices.Equal(a.Actions, []string{"helm", "job", "endpoint-probe", "endpoint-http"}) {
		t.Fatalf("endpoint approval omitted exact prerequisite capabilities: %v", a.Actions)
	}
	site.Spec.AllowedActions = []string{"job"}
	encoded, err = spec.Canonical(site)
	if err != nil {
		t.Fatal(err)
	}
	write(t, sitePath, encoded)
	result := h.command("run", "authorize", planPath, "--key", key, "--key-id", "customer", "--out", filepath.Join(h.dir, "denied.json"))
	if spec.ExitCode(result.err) != 16 {
		t.Fatalf("endpoint approval ignored Site capabilities: %v", result.err)
	}
}
