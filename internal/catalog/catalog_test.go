package catalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "catalog.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func testRecord() Record {
	return Record{Project: "plant", Site: "west", Kind: "Release", Body: json.RawMessage(`{"application":"qa","version":"1.2.0"}`)}
}

func TestImmutableRecordsAndDatabasePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.db")
	s, err := Open(context.Background(), "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private database permissions: %v %v", info, err)
	}
	r, err := s.Put(context.Background(), "operator", testRecord())
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.Put(context.Background(), "operator", testRecord())
	if err != nil || same.Digest != r.Digest {
		t.Fatalf("repeat changed identity: %v", err)
	}
	all, err := s.List(context.Background(), "plant", "west", "Release")
	if err != nil || len(all) != 1 {
		t.Fatalf("records=%d err=%v", len(all), err)
	}
	if _, err = s.Get(context.Background(), "other", "west", "Release", r.Digest); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-project read did not fail")
	}
	if _, err = s.Put(context.Background(), "operator", Record{Project: "plant", Kind: "Release", Body: json.RawMessage(`{"x":1,"x":2}`)}); err == nil {
		t.Fatal("duplicate JSON admitted")
	}
	if _, err = s.Put(context.Background(), "operator", Record{Project: "plant", Kind: "Release", Body: json.RawMessage(`{"x":1.1}`)}); err == nil {
		t.Fatal("noninteger signed value admitted")
	}
	if _, err = s.db.Exec(`UPDATE catalog_records SET body=? WHERE digest=?`, []byte(`{}`), r.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(context.Background(), "plant", "west", "Release", r.Digest); err == nil {
		t.Fatal("database tampering not detected")
	}
}

func testPacket(t *testing.T, seq int64) (Packet, []PacketKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := PacketBody{Issuer: "customer", Project: "plant", Site: "west", Sequence: seq, Records: []Record{testRecord()}}
	p, err := SignPacket(body, "customer", key)
	if err != nil {
		t.Fatal(err)
	}
	return p, []PacketKey{{ID: "customer", PublicKey: base64.StdEncoding.EncodeToString(pub), Projects: []string{"plant"}, Sites: []string{"west"}}}, key
}

func TestPacketIntegrityScopeAndReplay(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	p, keys, key := testPacket(t, 1)
	first, err := s.Import(ctx, "operator", p, keys)
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := s.Import(ctx, "operator", p, keys)
	if err != nil || first != repeat {
		t.Fatalf("duplicate import: %s %v", repeat, err)
	}
	var body PacketBody
	if err = strictJSON(p.Body, &body); err != nil {
		t.Fatal(err)
	}
	body.Records[0].Body = json.RawMessage(`{"version":"tampered"}`)
	changed, err := SignPacket(body, "customer", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Import(ctx, "operator", changed, keys); !errors.Is(err, ErrConflict) {
		t.Fatal("same sequence/different bytes accepted", err)
	}
	changed.Body = bytes.Replace(changed.Body, []byte("tampered"), []byte("changed!"), 1)
	if _, _, err = VerifyPacket(changed, keys); err == nil {
		t.Fatal("signature tampering accepted")
	}
	wrong := append([]PacketKey(nil), keys...)
	wrong[0].Projects = []string{"other"}
	if _, _, err = VerifyPacket(p, wrong); err == nil {
		t.Fatal("cross-project signer accepted")
	}
	body.Sequence = 2
	body.Records[0].Kind = "TrustPolicy"
	policyPacket, err := SignPacket(body, "customer", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = VerifyPacket(policyPacket, keys); err == nil {
		t.Fatal("policy metadata accepted without kind scope")
	}
	keys[0].Kinds = []string{"TrustPolicy"}
	if _, _, err = VerifyPacket(policyPacket, keys); err != nil {
		t.Fatal(err)
	}
}

func testHandler(t *testing.T, s *Store, keys []PacketKey) http.Handler {
	t.Helper()
	h, err := NewHandler(Config{Store: s, PacketKeys: keys, Origin: "http://127.0.0.1:8080", Actors: []Actor{{ID: "operator", TokenHash: TokenHash("operator-token-32bytes-at-least-long"), Projects: map[string][]string{"plant": {"publisher", "operator", "approver", "policy", "administrator"}}, Sites: []string{"west"}}, {ID: "stranger", TokenHash: TokenHash("stranger-token-32bytes-at-least-long"), Projects: map[string][]string{"other": {"operator"}}}, {ID: "support", TokenHash: TokenHash("support-token-32bytes-at-least-long"), Projects: map[string][]string{"plant": {"support"}}, Sites: []string{"west"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func request(h http.Handler, method, path, token, key string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Cinderlock-Request", "1")
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHTTPAuthenticationScopeCSRFAndIdempotency(t *testing.T) {
	s := testStore(t)
	h := testHandler(t, s, nil)
	token := "operator-token-32bytes-at-least-long"
	if w := request(h, "GET", "/api/v1/records?project=plant", "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(h, "GET", "/api/v1/records?project=plant", "stranger-token-32bytes-at-least-long", "", nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request(h, "POST", "/api/v1/records", token, "create", testRecord()); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	repeat := request(h, "POST", "/api/v1/records", token, "create", testRecord())
	if repeat.Code != 200 {
		t.Fatal(repeat.Code)
	}
	different := testRecord()
	different.Body = json.RawMessage(`{"version":"2"}`)
	if w := request(h, "POST", "/api/v1/records", token, "create", different); w.Code != 409 {
		t.Fatal("idempotency conflict", w.Code)
	}
	records, err := s.List(context.Background(), "plant", "west", "")
	if err != nil || len(records) != 1 {
		t.Fatalf("conflict mutated records: %d %v", len(records), err)
	}
	r := httptest.NewRequest("POST", "/api/v1/records", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://attacker.invalid")
	r.Header.Set("X-Cinderlock-Request", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin mutation accepted")
	}
	if err = ListenAddress("0.0.0.0:8080", false); err == nil {
		t.Fatal("public bind accepted")
	}
	if err = ListenAddress("127.0.0.1:8080", false); err != nil {
		t.Fatal(err)
	}
}

func TestPreviewImportAndNoExecution(t *testing.T) {
	s := testStore(t)
	p, keys, _ := testPacket(t, 1)
	h := testHandler(t, s, keys)
	token := "operator-token-32bytes-at-least-long"
	w := request(h, "POST", "/api/v1/import-previews", token, "preview", p)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var preview Preview
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	records, err := s.List(context.Background(), "plant", "west", "")
	if err != nil || len(records) != 0 {
		t.Fatal("preview mutated catalog records")
	}
	w = request(h, "POST", "/api/v1/imports", token, "admit", map[string]string{"preview": preview.Digest})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	records, err = s.List(context.Background(), "plant", "west", "")
	if err != nil || len(records) != 1 {
		t.Fatal("import missing")
	}
	w = request(h, "POST", "/api/v1/imports", "stranger-token-32bytes-at-least-long", "steal", map[string]string{"preview": preview.Digest})
	if w.Code != 404 {
		t.Fatalf("foreign preview readable: %d", w.Code)
	}
}

func TestSupportProjectionAndEscapedDashboard(t *testing.T) {
	s := testStore(t)
	run := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "run-1", State: "failed", Acceptance: "fail", Error: "synthetic-secret", TargetID: "private-target", SiteID: "sensitive-site", Domains: map[string]string{"workflow": "fail"}, Checks: []spec.CheckResult{{ID: "inference", Status: "fail", Reason: "customer document SECRET-DOC", Evidence: "/private/secret"}}}
	b, _ := spec.Canonical(run)
	stored, err := s.Put(context.Background(), "operator", Record{Project: "plant", Site: "west", Kind: "RunResult", Body: b})
	if err != nil {
		t.Fatal(err)
	}
	h := testHandler(t, s, nil)
	w := request(h, "GET", "/api/v1/records?project=plant", "support-token-32bytes-at-least-long", "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, secret := range []string{"synthetic-secret", "private-target", "sensitive-site", "SECRET-DOC", "/private/secret"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("support projection exposed", secret)
		}
	}
	_, err = s.Put(context.Background(), "operator", Record{Project: "plant", Site: "west", Kind: "Evidence", Body: json.RawMessage(`{"message":"<script>alert(1)</script>"}`)})
	if err != nil {
		t.Fatal(err)
	}
	w = request(h, "GET", "/", "operator-token-32bytes-at-least-long", "", nil)
	if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("unescaped HTML")
	}
	if !strings.Contains(w.Body.String(), "Skip to records") {
		t.Fatal("missing accessible skip link")
	}
	w = request(h, "POST", "/api/v1/export-previews", "operator-token-32bytes-at-least-long", "export-preview", map[string]any{"project": "plant", "site": "west", "kind": "RunResult", "digests": []string{stored.Digest}})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "SECRET-DOC") || strings.Contains(w.Body.String(), "private-target") {
		t.Fatal("default export included private fields")
	}
}

func TestPendingRequestCannotBlindlyRepeat(t *testing.T) {
	s := testStore(t)
	server := &Server{cfg: Config{Store: s}, policy: "policy"}
	if _, repeat, err := server.reserve(context.Background(), "actor", "write", "key", "body"); err != nil || repeat {
		t.Fatal(err)
	}
	if _, _, err := server.reserve(context.Background(), "actor", "write", "key", "body"); !errors.Is(err, ErrConflict) {
		t.Fatal("pending request repeated", err)
	}
}

func TestApprovalBindsActualPlanAndCurrentPolicy(t *testing.T) {
	s := testStore(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := spec.TrustPolicy{Header: spec.NewHeader("TrustPolicy"), Spec: spec.TrustSpec{Epoch: 1, Keys: []spec.TrustedKey{{ID: "vendor", PublicKey: base64.StdEncoding.EncodeToString(pub), Applications: []string{"qa"}, Channels: []string{"stable"}}}, AllowedActions: []string{"job"}}}
	policyDigest, _ := spec.Digest(policy)
	pb, _ := spec.Canonical(policy)
	if _, err = s.Put(context.Background(), "policy-owner", Record{Project: "plant", Site: "west", Kind: "TrustPolicy", Body: pb}); err != nil {
		t.Fatal(err)
	}
	plan := spec.Plan{Header: spec.NewHeader("Plan"), PolicyDigest: policyDigest, PolicyEpoch: 1, Snapshot: spec.TargetSnapshot{TargetID: "target-1"}, Operations: []spec.Operation{{ID: "deploy", Type: "job"}}, Executable: true}
	planDigest, _ := spec.Digest(plan)
	b, _ := spec.Canonical(plan)
	review, err := s.Put(context.Background(), "operator", Record{Project: "plant", Site: "west", Kind: "Plan", Body: b})
	if err != nil {
		t.Fatal(err)
	}
	h := testHandler(t, s, nil)
	r := ApprovalRequest{Project: "plant", Site: "west", PlanRecordDigest: review.Digest, PlanDigest: planDigest, PolicyDigest: policyDigest, PolicyEpoch: 1, TargetID: "target-1", Actions: []string{"job"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	w := request(h, "POST", "/api/v1/approvals", "operator-token-32bytes-at-least-long", "approve-1", r)
	if w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "not a signed execution Authorization") {
		t.Fatal("review metadata was presented as execution permission")
	}
	r.TargetID = "other-target"
	if w = request(h, "POST", "/api/v1/approvals", "operator-token-32bytes-at-least-long", "approve-wrong", r); w.Code != 409 {
		t.Fatalf("wrong target approved: %d", w.Code)
	}
	r.TargetID = "target-1"
	policy.Spec.Epoch = 2
	pb, _ = spec.Canonical(policy)
	if _, err = s.Put(context.Background(), "policy-owner", Record{Project: "plant", Site: "west", Kind: "TrustPolicy", Body: pb}); err != nil {
		t.Fatal(err)
	}
	if w = request(h, "POST", "/api/v1/approvals", "operator-token-32bytes-at-least-long", "approve-stale", r); w.Code != 409 {
		t.Fatalf("stale policy approved: %d", w.Code)
	}
}

func TestPreviewExpiryAndPolicyBinding(t *testing.T) {
	s := testStore(t)
	payload := json.RawMessage(`{"selection":[]}`)
	digest := digestBytes(payload)
	p := Preview{Digest: digest, Owner: "actor", Project: "plant", Purpose: "export", Policy: "policy-1", Payload: payload, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	if err := s.SavePreview(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Preview(context.Background(), digest, "actor", "export", "policy-2"); !errors.Is(err, ErrConflict) {
		t.Fatal("changed policy accepted preview")
	}
	if _, err := s.Preview(context.Background(), digest, "other", "export", "policy-1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("other actor read preview")
	}
}

func TestConcurrentIdempotencyKeyRejectsBeforeSecondMutation(t *testing.T) {
	s := testStore(t)
	handlers := []http.Handler{testHandler(t, s, nil), testHandler(t, s, nil)}
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := testRecord()
			r.Body = json.RawMessage([]byte(`{"version":"` + string(rune('a'+i)) + `"}`))
			w := request(handlers[i], "POST", "/api/v1/records", "operator-token-32bytes-at-least-long", "concurrent", r)
			results <- w.Code
		}(i)
	}
	wg.Wait()
	close(results)
	ok, conflict := 0, 0
	for status := range results {
		if status == 200 {
			ok++
		}
		if status == 409 {
			conflict++
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("success=%d conflicts=%d", ok, conflict)
	}
	rows, err := s.List(context.Background(), "plant", "west", "")
	if err != nil || len(rows) != 1 {
		t.Fatalf("distinct side effects occurred: %d %v", len(rows), err)
	}
}

func TestPostgresRoundTrip(t *testing.T) {
	dsn := os.Getenv("CINDERLOCK_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CINDERLOCK_TEST_POSTGRES_DSN not set; live PostgreSQL not exercised")
	}
	s, err := Open(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := testRecord()
	r.Project = "integration-" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	stored, err := s.Put(context.Background(), "integration", r)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Get(context.Background(), r.Project, r.Site, r.Kind, stored.Digest)
	if err != nil || loaded.Digest != stored.Digest {
		t.Fatalf("round trip: %v", err)
	}
}
