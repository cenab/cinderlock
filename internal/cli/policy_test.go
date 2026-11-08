package cli_test

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/trustupdate"
)

func TestPolicyCLIRequiresCurrentAuthorityAndExactAdmission(t *testing.T) {
	f := makeArtifactFixture(t)
	h := f.h
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/namespaces/test" {
			t.Errorf("unexpected target operation %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"test","uid":"test-namespace-uid"}}`))
	}))
	defer server.Close()
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	kubeconfig := filepath.Join(h.dir, "test.kubeconfig")
	write(t, kubeconfig, []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: test\n  cluster:\n    server: "+server.URL+"\n    certificate-authority-data: "+ca+"\ncontexts:\n- name: test\n  context:\n    cluster: test\n    namespace: test\n    user: test\nusers:\n- name: test\n  user:\n    token: local-test-only-token\ncurrent-context: test\n"))
	adminKey, adminPub := filepath.Join(h.dir, "admin.key"), filepath.Join(h.dir, "admin.pub")
	h.ok("trust", "keygen", "--private", adminKey, "--public", adminPub)
	current := filepath.Join(h.dir, "current-policy.json")
	h.ok("trust", "propose-update", f.policyPath, "--public", adminPub, "--key-id", "policy-admin", "--role", "policy", "--application", "*", "--channel", "*", "--out", current)
	site := spec.Site{Header: spec.NewHeader("Site"), Spec: spec.SiteSpec{Kubeconfig: kubeconfig, Context: "test", Namespace: "test", ReleaseName: "app", TrustPolicy: current, Profile: "test"}}
	site.Metadata.Name = "test"
	sitePath := filepath.Join(h.dir, "site.json")
	if err := spec.Write(sitePath, site); err != nil {
		t.Fatal(err)
	}
	var preview struct {
		Admitted     bool   `json:"admitted"`
		PolicyDigest string `json:"policyDigest"`
	}
	if err := json.Unmarshal(h.ok("trust", "admit-policy", "--site", sitePath), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Admitted || !spec.ValidDigest(preview.PolicyDigest) {
		t.Fatal(preview)
	}
	h.ok("trust", "admit-policy", "--site", sitePath, "--approved-digest", preview.PolicyDigest)
	candidate := filepath.Join(h.dir, "candidate-policy.json")
	h.ok("trust", "propose-update", current, "--public", f.publicPath, "--key-id", "release-v2", "--application", "cli-fixture", "--out", candidate)
	packet := filepath.Join(h.dir, "update.json")
	if r := h.command("trust", "update-sign", "--site", sitePath, "--candidate", candidate, "--key", f.keyPath, "--key-id", "release", "--decision-reference", "change-1", "--out", packet); r.err == nil {
		t.Fatal("vendor release key signed policy authority")
	}
	h.ok("trust", "update-sign", "--site", sitePath, "--candidate", candidate, "--key", adminKey, "--key-id", "policy-admin", "--decision-reference", "change-1", "--out", packet)
	update := decode[trustupdate.Preview](t, h.ok("trust", "update-preview", packet, "--site", sitePath))
	if update.PreviousEpoch != 2 || update.Candidate.Spec.Epoch != 3 {
		t.Fatal(update)
	}
	admittedPath := filepath.Join(h.dir, "admitted-policy.json")
	if r := h.command("trust", "update-admit", packet, "--site", sitePath, "--approved-digest", spec.Hash([]byte("wrong")), "--out", admittedPath); r.err == nil {
		t.Fatal("wrong packet approval accepted")
	}
	receipt := decode[trustupdate.Receipt](t, h.ok("trust", "update-admit", packet, "--site", sitePath, "--approved-digest", update.PacketDigest, "--out", admittedPath))
	if !receipt.Admitted || !receipt.CandidatePrepared {
		t.Fatal(receipt)
	}
	if r := h.command("trust", "admit-policy", "--site", sitePath, "--approved-digest", preview.PolicyDigest); r.err == nil {
		t.Fatal("old policy re-enrolled after floor advanced")
	}
}
