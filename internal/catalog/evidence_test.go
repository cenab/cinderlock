package catalog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestExternalEvidenceIsBoundSignedAndCannotUpgradeRunAcceptance(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	now := time.Now().UTC()
	record := storeComparisonRun(t, store, "gpu-lab", "1", now, []spec.CheckResult{{ID: "query", Domain: "workflow", Required: true, Status: "fail"}})
	var run spec.RunResult
	if err := spec.Decode(record.Record.Body, &run); err != nil {
		t.Fatal(err)
	}
	run.State = "failed"
	run.Acceptance = "fail"
	run.Domains["workflow"] = "fail"
	data, err := spec.Canonical(run)
	if err != nil {
		t.Fatal(err)
	}
	record, err = store.Put(ctx, "fixture", Record{Project: "plant", Site: "west", Kind: "RunResult", Body: data})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := store.Observation(ctx, "plant", "west", record.Digest)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := SubjectForObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := []EvidenceKey{{ID: "isolation-tester", PublicKey: base64.StdEncoding.EncodeToString(pub), Producer: "airgapproof", Versions: []string{"1.0"}, Projects: []string{"plant"}, Sites: []string{"west"}, Applications: []string{"document-qa"}, Profiles: []string{"gpu-lab"}, Scopes: []string{"network-isolation"}}}
	body := ExternalEvidence{Project: "plant", Site: "west", Producer: EvidenceProducer{Name: "airgapproof", Version: "1.0"}, Subject: subject, ObservedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), Scope: "network-isolation", ClaimedResult: "pass", Checks: []EvidenceCheck{{ID: "external-egress", Status: "pass"}}, Coverage: []string{"Declared startup network profile"}, Limitations: []string{"No functional inference or recovery test"}}
	signed, err := SignExternalEvidence(body, "isolation-tester", key)
	if err != nil {
		t.Fatal(err)
	}
	expected := EvidenceExpectation{Project: "plant", Site: "west", Subject: subject, Scope: "network-isolation"}
	verified, err := VerifyExternalEvidence(signed, keys, expected, now)
	if err != nil || verified.Acceptance != "attached_evidence_only" || verified.Evidence.ClaimedResult != "pass" {
		t.Fatal("valid signed observation rejected or strengthened", err)
	}
	h, err := NewHandler(Config{Store: store, Now: func() time.Time { return now }, EvidenceKeys: keys, Actors: []Actor{{ID: "operator", TokenHash: TokenHash("operator-token"), Projects: map[string][]string{"plant": {"operator"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	// A caller's subsequent config mutation cannot widen or revoke the handler's snapshot.
	keys[0].Profiles[0] = "other-profile"
	input := map[string]any{"project": "plant", "site": "west", "runDigest": record.Digest, "scope": "network-isolation", "evidence": signed}
	response := request(h, http.MethodPost, "/api/v1/external-evidence", "operator-token", "valid-evidence", input)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"acceptance":"attached_evidence_only"`) {
		t.Fatalf("evidence unavailable: %d %s", response.Code, response.Body.String())
	}
	var admitted struct {
		Record StoredRecord `json:"record"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &admitted); err != nil {
		t.Fatal(err)
	}
	verificationPath := "/api/v1/external-evidence?project=plant&site=west&digest=" + admitted.Record.Digest
	if r := request(h, http.MethodGet, verificationPath, "operator-token", "", nil); r.Code != 200 {
		t.Fatal("current verification unavailable", r.Code)
	}
	original, err := store.Get(ctx, "plant", "west", "RunResult", record.Digest)
	if err != nil || string(original.Record.Body) != string(record.Record.Body) {
		t.Fatal("external pass changed the failed run", err)
	}
	tests := []struct {
		name   string
		change func(*ExternalEvidence)
	}{
		{"wrong-bundle", func(b *ExternalEvidence) { b.Subject.BundleDigest = spec.Hash([]byte("different")) }},
		{"wrong-run", func(b *ExternalEvidence) { b.Subject.RunID = "another-run" }},
		{"wrong-plan", func(b *ExternalEvidence) { b.Subject.PlanDigest = spec.Hash([]byte("another-plan")) }},
		{"wrong-profile", func(b *ExternalEvidence) { b.Subject.Profile = "other" }},
		{"expired", func(b *ExternalEvidence) {
			b.ObservedAt = now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
			b.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
		}},
		{"future", func(b *ExternalEvidence) { b.ObservedAt = now.Add(time.Minute).Format(time.RFC3339Nano) }},
		{"unknown-version", func(b *ExternalEvidence) { b.Producer.Version = "unadmitted-version" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := body
			test.change(&changed)
			bad, err := SignExternalEvidence(changed, "isolation-tester", key)
			if err != nil {
				t.Fatal(err)
			}
			input["evidence"] = bad
			r := request(h, http.MethodPost, "/api/v1/external-evidence", "operator-token", test.name, input)
			if r.Code == 200 {
				t.Fatal("invalid external evidence admitted")
			}
		})
	}
	keys[0].Profiles[0] = "gpu-lab"
	keys[0].NotAfter = now.Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err = VerifyExternalEvidence(signed, keys, expected, now); err == nil {
		t.Fatal("expired producer key scope admitted")
	}
	keys[0].NotAfter = ""
	keys[0].Revoked = true
	if _, err = VerifyExternalEvidence(signed, keys, expected, now); err == nil {
		t.Fatal("revoked evidence key admitted")
	}
	keys[0].Revoked = false
	confused := signed
	confused.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(packetDomain), signed.Body...)))
	if _, err = VerifyExternalEvidence(confused, keys, expected, now); err == nil {
		t.Fatal("catalog packet signature accepted as external evidence")
	}
	tampered := signed
	tampered.Body = append(json.RawMessage(nil), signed.Body...)
	tampered.Body = []byte(strings.Replace(string(tampered.Body), "Declared startup", "Modified startup", 1))
	if _, err = VerifyExternalEvidence(tampered, keys, expected, now); err == nil {
		t.Fatal("tampered external evidence accepted")
	}
	futureHandler, err := NewHandler(Config{Store: store, Now: func() time.Time { return now.Add(2 * time.Hour) }, EvidenceKeys: keys, Actors: []Actor{{ID: "operator", TokenHash: TokenHash("operator-token"), Projects: map[string][]string{"plant": {"operator"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if r := request(futureHandler, http.MethodGet, verificationPath, "operator-token", "", nil); r.Code == 200 {
		t.Fatal("old admission remained valid after evidence scope expired")
	}
}
