package catalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

func runtimeEvidenceFixture(t *testing.T) (*Store, http.Handler, StoredRecord, ExternalEvidence, ed25519.PrivateKey) {
	t.Helper()
	store, err := Open(context.Background(), "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := time.Now().UTC()
	record := storeComparisonRun(t, store, "cpu-lab", "1", now, []spec.CheckResult{{ID: "query", Domain: "workflow", Required: true, Status: "fail"}})
	o, err := store.Observation(context.Background(), "plant", "west", record.Digest)
	if err != nil {
		t.Fatal(err)
	}
	o.Run.State, o.Run.Acceptance = "failed", "fail"
	data, err := spec.Canonical(o.Run)
	if err != nil {
		t.Fatal(err)
	}
	record, err = store.Put(context.Background(), "fixture", Record{Project: "plant", Site: "west", Kind: "RunResult", Body: data})
	if err != nil {
		t.Fatal(err)
	}
	subject, err := SubjectForObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := []EvidenceKey{{ID: "runtime-observer", PublicKey: base64.StdEncoding.EncodeToString(public), Producer: "runtime-observer", Versions: []string{"1.0"}, Projects: []string{"plant"}, Sites: []string{"west"}, Applications: []string{"document-qa"}, Profiles: []string{"cpu-lab"}, Scopes: []string{"network-isolation"}}}
	h, err := NewHandler(Config{Store: store, Now: func() time.Time { return now }, EvidenceKeys: keys, Actors: []Actor{{ID: "operator", TokenHash: TokenHash("operator-token"), Projects: map[string][]string{"plant": {"operator"}}, Sites: []string{"west"}}}})
	if err != nil {
		t.Fatal(err)
	}
	port, dropped := 443, int64(2)
	body := ExternalEvidence{APIVersion: spec.APIVersion, Kind: "ExternalEvidence", SchemaVersion: 1, Project: "plant", Site: "west", Producer: EvidenceProducer{Name: "runtime-observer", Version: "1.0"}, Subject: subject, ObservedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), Scope: "network-isolation", ClaimedResult: "pass", Checks: []EvidenceCheck{{ID: "declared-egress", Status: "pass"}}, Coverage: []string{"Producer-declared TCP observation window"}, Limitations: []string{"Synthetic fixture, no collector executed; ICMP and other protocols unobserved"}, RuntimeCapture: &RuntimeCapture{SchemaVersion: 1, StartedAt: now.Add(-3 * time.Minute).Format(time.RFC3339Nano), FinishedAt: now.Add(-2 * time.Minute).Format(time.RFC3339Nano), ObservedProtocols: []string{"tcp"}, UnsupportedProtocols: []string{"dns", "udp"}, DroppedEvents: &dropped, Observations: []RuntimeObservation{{ID: "connect-1", ObservedAt: now.Add(-2 * time.Minute).Format(time.RFC3339Nano), Protocol: "tcp", Source: RuntimeSource{Namespace: "application", Container: "api", Process: "worker"}, Destination: RuntimeDestination{Address: "192.0.2.1", Name: "updates.example.test", Port: &port}, Outcome: "blocked", ProducerConfidence: "high"}}}}
	return store, h, record, body, private
}

func signedRuntimeInput(t *testing.T, body any, private ed25519.PrivateKey) SignedExternalEvidence {
	t.Helper()
	data, err := spec.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	// External producers can sign malformed bodies without using the local signer.
	return SignedExternalEvidence{Body: data, KeyID: "runtime-observer", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(externalEvidenceDomain), data...)))}
}

func TestRuntimeCaptureRESTPreservesClaimsAndGapsWithoutChangingAcceptance(t *testing.T) {
	store, h, record, body, private := runtimeEvidenceFixture(t)
	signed, err := SignExternalEvidence(body, "runtime-observer", private)
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"project": "plant", "site": "west", "runDigest": record.Digest, "scope": "network-isolation", "evidence": signed}
	response := request(h, http.MethodPost, "/api/v1/external-evidence", "operator-token", "runtime", input)
	if response.Code != http.StatusOK {
		t.Fatal("runtime capture admission failed", response.Code, response.Body.String())
	}
	var admitted struct {
		Record       StoredRecord             `json:"record"`
		Verification VerifiedExternalEvidence `json:"verification"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &admitted); err != nil {
		t.Fatal(err)
	}
	verification := admitted.Verification
	if verification.Acceptance != "attached_evidence_only" || verification.Evidence.ClaimedResult != body.ClaimedResult || !reflect.DeepEqual(verification.Evidence.RuntimeCapture, body.RuntimeCapture) || !strings.Contains(verification.Notice, "attempts do not establish functional dependence") {
		t.Fatal("runtime claims or gaps were lost or strengthened", verification)
	}
	response = request(h, http.MethodGet, "/api/v1/external-evidence?project=plant&site=west&digest="+admitted.Record.Digest, "operator-token", "", nil)
	var reread VerifiedExternalEvidence
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &reread) != nil || !reflect.DeepEqual(reread.Evidence.RuntimeCapture, body.RuntimeCapture) {
		t.Fatal("stored runtime capture did not round trip", response.Code, response.Body.String())
	}
	original, err := store.Get(context.Background(), "plant", "west", "RunResult", record.Digest)
	if err != nil || !bytes.Equal(original.Record.Body, record.Record.Body) {
		t.Fatal("external runtime claim changed failed native acceptance", err)
	}
}

func TestRuntimeCaptureEmptyAndUnknownScopeDoesNotBecomeIndependenceProof(t *testing.T) {
	_, h, record, body, private := runtimeEvidenceFixture(t)
	body.RuntimeCapture.Observations = []RuntimeObservation{}
	body.RuntimeCapture.DroppedEvents = nil
	body.RuntimeCapture.DropUnknownReason = "not_collected"
	signed, err := SignExternalEvidence(body, "runtime-observer", private)
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"project": "plant", "site": "west", "runDigest": record.Digest, "scope": "network-isolation", "evidence": signed}
	response := request(h, http.MethodPost, "/api/v1/external-evidence", "operator-token", "empty-runtime", input)
	var admitted struct {
		Verification VerifiedExternalEvidence `json:"verification"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &admitted) != nil {
		t.Fatal("explicit empty capture rejected", response.Code, response.Body.String())
	}
	if !strings.Contains(admitted.Verification.Notice, "No observations in declared capture scope; this is not proof of zero external dependency") || admitted.Verification.Evidence.RuntimeCapture.DroppedEvents != nil || admitted.Verification.Evidence.RuntimeCapture.DropUnknownReason != "not_collected" || admitted.Verification.Acceptance != "attached_evidence_only" {
		t.Fatal("empty or unknown-loss capture was strengthened", admitted.Verification)
	}
	body.RuntimeCapture.Observations = []RuntimeObservation{{ID: "unknown-source", ObservedAt: body.RuntimeCapture.FinishedAt, Protocol: "tcp", Source: RuntimeSource{Namespace: "application", UnknownReason: "permission_denied"}, Destination: RuntimeDestination{UnknownReason: "not_available"}, Outcome: "attempted", ProducerConfidence: "unknown"}}
	signed, err = SignExternalEvidence(body, "runtime-observer", private)
	if err != nil {
		t.Fatal("collector was forced to invent attribution or destination details", err)
	}
	input["evidence"] = signed
	if response = request(h, http.MethodPost, "/api/v1/external-evidence", "operator-token", "unknown-runtime", input); response.Code != http.StatusOK {
		t.Fatal("explicitly unknown attribution rejected", response.Code)
	}
}

func TestRuntimeCaptureRESTRejectsMalformedSignedObservations(t *testing.T) {
	_, h, record, body, private := runtimeEvidenceFixture(t)
	tests := []struct {
		name   string
		change func(*ExternalEvidence)
	}{
		{"wrong-scope", func(b *ExternalEvidence) { b.Scope = "security-scan" }},
		{"changed-subject", func(b *ExternalEvidence) { b.Subject.RunID = "another-run" }},
		{"unknown-capture-version", func(b *ExternalEvidence) { b.RuntimeCapture.SchemaVersion = 2 }},
		{"missing-source-reason", func(b *ExternalEvidence) { b.RuntimeCapture.Observations[0].Source.Process = "" }},
		{"command-arguments", func(b *ExternalEvidence) {
			b.RuntimeCapture.Observations[0].Source.Process = "worker --token=DO-NOT-IMPORT"
		}},
		{"address-is-url", func(b *ExternalEvidence) {
			b.RuntimeCapture.Observations[0].Destination.Address = "https://example.test"
		}},
		{"name-is-url", func(b *ExternalEvidence) {
			b.RuntimeCapture.Observations[0].Destination.Name = "https://example.test/token"
		}},
		{"invalid-port", func(b *ExternalEvidence) { *b.RuntimeCapture.Observations[0].Destination.Port = 65536 }},
		{"unknown-port-without-reason", func(b *ExternalEvidence) { b.RuntimeCapture.Observations[0].Destination.Port = nil }},
		{"undeclared-protocol", func(b *ExternalEvidence) { b.RuntimeCapture.Observations[0].Protocol = "dns" }},
		{"unknown-protocol", func(b *ExternalEvidence) { b.RuntimeCapture.ObservedProtocols[0] = "icmp" }},
		{"missing-protocol-gap", func(b *ExternalEvidence) { b.RuntimeCapture.UnsupportedProtocols = nil }},
		{"overlapping-protocol-scope", func(b *ExternalEvidence) { b.RuntimeCapture.UnsupportedProtocols[0] = "tcp" }},
		{"negative-dropped-events", func(b *ExternalEvidence) { *b.RuntimeCapture.DroppedEvents = -1 }},
		{"unknown-loss-without-reason", func(b *ExternalEvidence) { b.RuntimeCapture.DroppedEvents = nil }},
		{"event-after-window", func(b *ExternalEvidence) { b.RuntimeCapture.Observations[0].ObservedAt = b.ObservedAt }},
		{"invalid-event-time", func(b *ExternalEvidence) { b.RuntimeCapture.Observations[0].ObservedAt = "yesterday" }},
		{"nonpositive-window", func(b *ExternalEvidence) { b.RuntimeCapture.StartedAt = b.RuntimeCapture.FinishedAt }},
		{"capture-after-evidence", func(b *ExternalEvidence) { b.RuntimeCapture.FinishedAt = b.ExpiresAt }},
		{"duplicate-id", func(b *ExternalEvidence) {
			b.RuntimeCapture.Observations = append(b.RuntimeCapture.Observations, b.RuntimeCapture.Observations[0])
		}},
		{"missing-observations", func(b *ExternalEvidence) { b.RuntimeCapture.Observations = nil }},
		{"oversized-observations", func(b *ExternalEvidence) {
			first := b.RuntimeCapture.Observations[0]
			b.RuntimeCapture.Observations = make([]RuntimeObservation, 129)
			for i := range b.RuntimeCapture.Observations {
				b.RuntimeCapture.Observations[i] = first
				b.RuntimeCapture.Observations[i].ID = fmt.Sprintf("event-%d", i)
			}
		}},
		{"invalid-confidence", func(b *ExternalEvidence) { b.RuntimeCapture.Observations[0].ProducerConfidence = "certain" }},
		{"udp-connected", func(b *ExternalEvidence) {
			b.RuntimeCapture.ObservedProtocols = []string{"udp"}
			b.RuntimeCapture.UnsupportedProtocols = []string{"tcp", "dns"}
			b.RuntimeCapture.Observations[0].Protocol = "udp"
			b.RuntimeCapture.Observations[0].Outcome = "connected"
		}},
		{"dns-name-unknown-without-reason", func(b *ExternalEvidence) {
			b.RuntimeCapture.ObservedProtocols = []string{"dns"}
			b.RuntimeCapture.UnsupportedProtocols = []string{"tcp", "udp"}
			b.RuntimeCapture.Observations[0].Protocol = "dns"
			b.RuntimeCapture.Observations[0].Destination.Name = ""
			b.RuntimeCapture.Observations[0].Outcome = "attempted"
		}},
	}
	data, err := spec.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var changed ExternalEvidence
			if err := spec.Decode(data, &changed); err != nil {
				t.Fatal(err)
			}
			test.change(&changed)
			signed := signedRuntimeInput(t, changed, private)
			input := map[string]any{"project": "plant", "site": "west", "runDigest": record.Digest, "scope": "network-isolation", "evidence": signed}
			response := request(h, http.MethodPost, "/api/v1/external-evidence", "operator-token", test.name, input)
			if response.Code != http.StatusBadRequest {
				t.Fatal("malformed signed runtime observation admitted", response.Code, response.Body.String())
			}
		})
	}
	var raw map[string]any
	if err = json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	capture := raw["runtimeCapture"].(map[string]any)
	capture["observations"].([]any)[0].(map[string]any)["rawLog"] = "DO-NOT-IMPORT-RAW-TRAFFIC"
	input := map[string]any{"project": "plant", "site": "west", "runDigest": record.Digest, "scope": "network-isolation", "evidence": signedRuntimeInput(t, raw, private)}
	if response := request(h, http.MethodPost, "/api/v1/external-evidence", "operator-token", "raw-log", input); response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "DO-NOT-IMPORT") {
		t.Fatal("raw log was admitted or reflected", response.Code, response.Body.String())
	}
}
