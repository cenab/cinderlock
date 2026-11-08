package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestLocalNotificationRequiresConfiguredRuleAndReviewedExport(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	now := time.Now().UTC()
	record := storeComparisonRun(t, store, "gpu-lab", "1", now, []spec.CheckResult{{ID: "query", Domain: "workflow", Required: true, Status: "fail"}})
	var run spec.RunResult
	if err := spec.Decode(record.Record.Body, &run); err != nil {
		t.Fatal(err)
	}
	run.Error = "DO-NOT-EXPORT-RAW-CUSTOMER-DIAGNOSTIC"
	run.State = "failed"
	run.Acceptance = "fail"
	body, err := spec.Canonical(run)
	if err != nil {
		t.Fatal(err)
	}
	record, err = store.Put(ctx, "fixture", Record{Project: "plant", Site: "west", Kind: "RunResult", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{ID: "operator", TokenHash: TokenHash("operator-token"), Projects: map[string][]string{"plant": {"operator"}}}
	cfg := Config{Store: store, Actors: []Actor{actor}}
	disabled, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"project": "plant", "site": "west", "runDigest": record.Digest}
	r := request(disabled, http.MethodPost, "/api/v1/notification-queues", "operator-token", "disabled", input)
	if r.Code != 200 || strings.TrimSpace(r.Body.String()) != "[]" {
		t.Fatalf("unconfigured local queue activated: %d %s", r.Code, r.Body.String())
	}
	cfg.NotificationRules = []NotificationRule{{ID: "failures", Project: "plant", Site: "west", States: []string{"failed"}}}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r = request(h, http.MethodPost, "/api/v1/notification-queues", "operator-token", "enqueue", input)
	if r.Code != 200 {
		t.Fatalf("queue unavailable: %d %s", r.Code, r.Body.String())
	}
	var notes []QueuedNotification
	if err = json.Unmarshal(r.Body.Bytes(), &notes); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 || notes[0].Notification.RecordDigest != record.Digest || notes[0].Notification.Summary.Acceptance != "fail" || strings.Contains(r.Body.String(), run.Error) {
		t.Fatal("notification lost scope or exposed raw diagnostics", r.Body.String())
	}
	id := notes[0].Notification.ID
	repeated := request(h, http.MethodPost, "/api/v1/notification-queues", "operator-token", "enqueue-again", input)
	var again []QueuedNotification
	if err = json.Unmarshal(repeated.Body.Bytes(), &again); err != nil || len(again) != 1 || again[0].Digest != notes[0].Digest {
		t.Fatal("repeat changed immutable queued observation", err)
	}
	r = request(h, http.MethodPost, "/api/v1/notification-previews", "operator-token", "preview", map[string]any{"project": "plant", "site": "west", "ids": []string{id}})
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var preview Preview
	if err = json.Unmarshal(r.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	bad := request(h, http.MethodPost, "/api/v1/notification-exports", "operator-token", "bad-approval", map[string]string{"preview": preview.Digest, "approvedDigest": spec.Hash([]byte("wrong"))})
	if bad.Code == 200 {
		t.Fatal("unreviewed notification exported")
	}
	pending, err := store.PendingNotifications(ctx, "plant", "west")
	if err != nil || len(pending) != 1 {
		t.Fatal("denied export mutated queue", err)
	}
	good := request(h, http.MethodPost, "/api/v1/notification-exports", "operator-token", "export", map[string]string{"preview": preview.Digest, "approvedDigest": preview.Digest})
	if good.Code != 200 || !strings.Contains(good.Body.String(), `"sent":false`) || strings.Contains(good.Body.String(), run.Error) {
		t.Fatal("export masked delivery or leaked data", good.Code, good.Body.String())
	}
	pending, err = store.PendingNotifications(ctx, "plant", "west")
	if err != nil || len(pending) != 0 {
		t.Fatal("approved local export still pending", err)
	}
	if r = request(h, http.MethodGet, "/api/v1/notifications?project=other&site=west", "operator-token", "", nil); r.Code != 403 {
		t.Fatal("cross-project queue visible", r.Code)
	}
}

func TestPostgresLocalOutboxRoundTrip(t *testing.T) {
	dsn := os.Getenv("CINDERLOCK_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CINDERLOCK_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal("PostgreSQL catalog unavailable")
	}
	defer store.Close()
	project := fmt.Sprintf("outbox-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	run := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "postgres-fixture", SiteID: "west", State: "failed", Acceptance: "fail"}
	data, err := spec.Canonical(run)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Put(ctx, "operator", Record{Project: project, Site: "west", Kind: "RunResult", Body: data})
	if err != nil {
		t.Fatal(err)
	}
	notes, err := store.QueueNotifications(ctx, "operator", project, "west", record.Digest, []NotificationRule{{ID: "failed-run", Project: project, Site: "west", States: []string{"failed"}}}, now)
	if err != nil || len(notes) != 1 || notes[0].Notification.Summary.RunID != run.RunID {
		t.Fatal("PostgreSQL queue failed", err)
	}
	policy := spec.Hash([]byte("postgres-fixture-policy"))
	preview, err := store.NotificationPreview(ctx, "operator", policy, project, "west", []string{notes[0].Notification.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := store.ExportNotifications(ctx, "operator", policy, preview.Digest, preview.Digest, now)
	if err != nil || !strings.Contains(string(payload), run.RunID) {
		t.Fatal("PostgreSQL reviewed export failed", err)
	}
	pending, err := store.PendingNotifications(ctx, project, "west")
	if err != nil || len(pending) != 0 {
		t.Fatal("PostgreSQL export not recorded", err)
	}
}
