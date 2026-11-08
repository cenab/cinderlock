package cli_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/catalog"
	"github.com/cenab/cinderlock/internal/spec"
)

func TestRuntimeCaptureEvidenceCLI(t *testing.T) {
	h := newHarness(t)
	recordObservation(t, h, "runtime-run", "1.0.0")
	subject := decode[catalog.EvidenceSubject](t, h.ok("evidence", "subject", "runtime-run"))
	keyPath, pubPath := filepath.Join(h.dir, "runtime.key"), filepath.Join(h.dir, "runtime.pub")
	h.ok("trust", "keygen", "--private", keyPath, "--public", pubPath)
	public, err := bundle.ParsePublicKey(string(read(t, pubPath)))
	if err != nil {
		t.Fatal(err)
	}
	keys := []catalog.EvidenceKey{{ID: "runtime-observer", PublicKey: base64.StdEncoding.EncodeToString(public), Producer: "runtime-observer", Versions: []string{"1.0.0"}, Projects: []string{"project"}, Sites: []string{"test-site"}, Applications: []string{"fixture"}, Profiles: []string{"cpu-test"}, Scopes: []string{"network-isolation"}}}
	keysPath := filepath.Join(h.dir, "runtime-keys.json")
	if err = spec.Write(keysPath, keys); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	body := catalog.ExternalEvidence{Project: "project", Site: "test-site", Producer: catalog.EvidenceProducer{Name: "runtime-observer", Version: "1.0.0"}, Subject: subject, ObservedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), Scope: "network-isolation", ClaimedResult: "not_tested", Checks: []catalog.EvidenceCheck{{ID: "runtime-capture", Status: "not_tested"}}, Coverage: []string{"Synthetic DNS/TCP/UDP observations"}, Limitations: []string{"No collector was executed; other protocols and functional dependence are unqualified"}}
	bodyJSON, err := spec.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]json.RawMessage
	if err = json.Unmarshal(bodyJSON, &input); err != nil {
		t.Fatal(err)
	}
	stamp := now.Add(-2 * time.Minute).Format(time.RFC3339Nano)
	capture, err := spec.Canonical(map[string]any{
		"schemaVersion": 1, "startedAt": now.Add(-3 * time.Minute).Format(time.RFC3339Nano), "finishedAt": stamp,
		"observedProtocols": []string{"dns", "tcp", "udp"}, "unsupportedProtocols": []string{}, "droppedEvents": 0,
		"observations": []any{
			map[string]any{"id": "dns-1", "observedAt": stamp, "protocol": "dns", "source": map[string]string{"namespace": "application", "container": "api", "process": "worker"}, "destination": map[string]any{"address": "192.0.2.53", "name": "updates.example.test", "port": 53}, "outcome": "resolved", "producerConfidence": "medium"},
			map[string]any{"id": "tcp-1", "observedAt": stamp, "protocol": "tcp", "source": map[string]string{"namespace": "application", "container": "api", "process": "worker"}, "destination": map[string]any{"name": "updates.example.test", "port": 443}, "outcome": "connected", "producerConfidence": "high"},
			map[string]any{"id": "udp-1", "observedAt": stamp, "protocol": "udp", "source": map[string]string{"unknownReason": "not_collected"}, "destination": map[string]any{"unknownReason": "not_available"}, "outcome": "attempted", "producerConfidence": "unknown"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	input["runtimeCapture"] = capture
	bodyPath, packetPath := filepath.Join(h.dir, "runtime-body.json"), filepath.Join(h.dir, "runtime-evidence.json")
	if err = spec.Write(bodyPath, input); err != nil {
		t.Fatal(err)
	}
	h.ok("evidence", "sign", bodyPath, "--key", keyPath, "--key-id", "runtime-observer", "--out", packetPath)
	verified := decode[catalog.VerifiedExternalEvidence](t, h.ok("evidence", "verify", packetPath, "--keys", keysPath, "--run", "runtime-run", "--project", "project", "--scope", "network-isolation"))
	received, err := spec.Canonical(verified.Evidence.RuntimeCapture)
	if err != nil || !bytes.Equal(received, capture) || verified.Integrity != "verified" || verified.Acceptance != "attached_evidence_only" {
		t.Fatal("runtime observations were lost or strengthened", err, verified)
	}
	if result := h.command("evidence", "verify", packetPath, "--keys", keysPath, "--run", "runtime-run", "--project", "project", "--scope", "security-scan"); result.err == nil {
		t.Fatal("runtime evidence accepted under another scope")
	}
	var signed catalog.SignedExternalEvidence
	if err = spec.Read(packetPath, &signed); err != nil {
		t.Fatal(err)
	}
	signed.Body = bytes.Replace(signed.Body, []byte(`"connected"`), []byte(`"blocked"`), 1)
	tamperedPath := filepath.Join(h.dir, "runtime-tampered.json")
	if err = spec.Write(tamperedPath, signed); err != nil {
		t.Fatal(err)
	}
	if result := h.command("evidence", "verify", tamperedPath, "--keys", keysPath, "--run", "runtime-run", "--project", "project", "--scope", "network-isolation"); result.err == nil {
		t.Fatal("tampered runtime observation verified")
	}
}
