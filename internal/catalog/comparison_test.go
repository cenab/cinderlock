package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

func storeComparisonRun(t *testing.T, store *Store, profile, version string, observed time.Time, checks []spec.CheckResult) StoredRecord {
	t.Helper()
	site := spec.Site{Header: spec.NewHeader("Site"), Spec: spec.SiteSpec{Profile: profile}}
	site.Metadata.Name = "west"
	siteDigest, err := spec.Digest(site)
	if err != nil {
		t.Fatal(err)
	}
	plan := spec.Plan{Header: spec.NewHeader("Plan"), BundleDigest: spec.Hash([]byte(version)), SiteDigest: siteDigest, Snapshot: spec.TargetSnapshot{SiteID: "west", TargetID: "target-west"}, Checks: []spec.Check{}, RequiredChecks: []string{}}
	plan.Metadata = spec.Metadata{Application: "document-qa", Version: version}
	for _, c := range checks {
		plan.Checks = append(plan.Checks, spec.Check{ID: c.ID, Type: "http", Domain: c.Domain, Required: c.Required, URL: "http://qa:8080/" + c.ID, ExpectedStatus: 200})
		if c.Required {
			plan.RequiredChecks = append(plan.RequiredChecks, c.ID)
		}
	}
	planDigest, err := spec.Digest(plan)
	if err != nil {
		t.Fatal(err)
	}
	run := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "run-" + version, PlanDigest: planDigest, BundleDigest: plan.BundleDigest, SiteID: "west", TargetID: "target-west", State: "succeeded", Acceptance: "pass", StartedAt: observed.Add(-time.Minute).Format(time.RFC3339Nano), FinishedAt: observed.Format(time.RFC3339Nano), Checks: checks, Domains: map[string]string{"workflow": "pass", "readiness": "pass"}}
	run.Metadata = plan.Metadata
	var out StoredRecord
	for _, v := range []struct {
		kind string
		body any
	}{{"Site", site}, {"Plan", plan}, {"RunResult", run}} {
		b, e := spec.Canonical(v.body)
		if e != nil {
			t.Fatal(e)
		}
		out, e = store.Put(context.Background(), "fixture", Record{Project: "plant", Site: "west", Kind: v.kind, Body: b})
		if e != nil {
			t.Fatal(e)
		}
	}
	return out
}

func TestComparisonExposesCoverageChangesWithoutFreshHealthClaim(t *testing.T) {
	store := testStore(t)
	now := time.Date(2026, 11, 7, 23, 0, 0, 0, time.UTC)
	before := storeComparisonRun(t, store, "gpu-lab", "1", now.Add(-48*time.Hour), []spec.CheckResult{{ID: "query", Domain: "workflow", Required: true, Status: "fail"}, {ID: "ingestion", Domain: "workflow", Required: true, Status: "pass"}})
	after := storeComparisonRun(t, store, "gpu-lab", "2", now.Add(-time.Hour), []spec.CheckResult{{ID: "query", Domain: "workflow", Required: true, Status: "pass"}, {ID: "restart", Domain: "recovery", Required: true, Status: "pass"}})
	h, err := NewHandler(Config{Store: store, Now: func() time.Time { return now }, Actors: []Actor{{ID: "reader", TokenHash: TokenHash("local-reader-token"), Projects: map[string][]string{"plant": {"auditor"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{"project": {"plant"}, "site": {"west"}, "before": {before.Digest}, "after": {after.Digest}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/comparisons?"+query.Encode(), nil)
	req.Header.Set("Authorization", "Bearer local-reader-token")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("comparison unavailable: status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Comparable bool     `json:"comparable"`
		Reasons    []string `json:"reasons"`
		Before     struct {
			Freshness string `json:"freshness"`
		} `json:"before"`
		After struct {
			Freshness string `json:"freshness"`
		} `json:"after"`
		Checks []struct{ ID, Change, Before, After string } `json:"checks"`
		Notice string                                       `json:"notice"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Comparable || result.Before.Freshness != "stale" || result.After.Freshness != "recent_observation" {
		t.Fatalf("misleading comparison: %s", response.Body.String())
	}
	changes := map[string]string{}
	for _, c := range result.Checks {
		changes[c.ID] = c.Change
	}
	if changes["query"] != "changed" || changes["ingestion"] != "missing" || changes["restart"] != "new" {
		t.Fatal(changes)
	}
	if !strings.Contains(result.Notice, "live") || len(result.Reasons) == 0 {
		t.Fatal("missing observation or coverage limitation")
	}
	query.Set("project", "other")
	req = httptest.NewRequest(http.MethodGet, "/api/v1/comparisons?"+query.Encode(), nil)
	req.Header.Set("Authorization", "Bearer local-reader-token")
	response = httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusForbidden {
		t.Fatal("cross-project comparison admitted", response.Code)
	}
}

func TestComparisonUsesEffectiveRequiredContract(t *testing.T) {
	store := testStore(t)
	now := time.Now().UTC()
	record := storeComparisonRun(t, store, "gpu-lab", "1", now, []spec.CheckResult{{ID: "query", Domain: "workflow", Required: true, Status: "pass"}})
	o, err := store.Observation(context.Background(), "plant", "west", record.Digest)
	if err != nil {
		t.Fatal(err)
	}
	// The engine unions these two sources when constructing each check result.
	o.Plan.Checks[0].Required = false
	o.Plan.RequiredChecks = []string{"query"}
	o.Run.PlanDigest, err = spec.Digest(o.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CompareObservations(o, o, now, time.Hour); err != nil {
		t.Fatalf("valid required-by-ID result rejected: %v", err)
	}
}

func TestComparisonRejectsUnboundSubjectsAndLabelsProfileChanges(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	now := time.Now().UTC()
	before := storeComparisonRun(t, store, "profile-a", "1", now.Add(-time.Hour), []spec.CheckResult{{ID: "query", Domain: "workflow", Required: true, Status: "fail"}})
	after := storeComparisonRun(t, store, "profile-b", "2", now, []spec.CheckResult{{ID: "query", Domain: "workflow", Required: true, Status: "pass"}})
	a, err := store.Observation(ctx, "plant", "west", before.Digest)
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.Observation(ctx, "plant", "west", after.Digest)
	if err != nil {
		t.Fatal(err)
	}
	a.Run.Domains["workflow"] = "fail"
	result, err := CompareObservations(a, b, now, 24*time.Hour)
	if err != nil || result.Comparable || !contains(result.Reasons, "profile_changed") {
		t.Fatal("changed profile silently compared", err, result)
	}
	found := false
	for _, domain := range result.Domains {
		if domain.ID == "workflow" && domain.Before == "fail" && domain.After == "pass" && domain.Change == "changed" {
			found = true
		}
	}
	if !found {
		t.Fatal("observed domain change lost")
	}
	for _, mutate := range []func(*Observation){func(o *Observation) { o.Run.TargetID = "other-target" }, func(o *Observation) { o.Run.BundleDigest = spec.Hash([]byte("wrong")) }, func(o *Observation) { o.Run.PlanDigest = spec.Hash([]byte("wrong")) }, func(o *Observation) { o.Site.Spec.Profile = "unbound-profile" }} {
		bad := b
		mutate(&bad)
		if _, err = CompareObservations(a, bad, now, time.Hour); err == nil {
			t.Fatal("unbound observation compared")
		}
	}
}

func TestComparisonAcceptsBoundRecoveryHistory(t *testing.T) {
	store := testStore(t)
	now := time.Now().UTC()
	record := storeComparisonRun(t, store, "gpu-lab", "1", now, []spec.CheckResult{{ID: "query", Domain: "workflow", Required: true, Status: "pass"}})
	o, err := store.Observation(context.Background(), "plant", "west", record.Digest)
	if err != nil {
		t.Fatal(err)
	}
	o.Plan.Kind = "RecoveryPlan"
	o.Plan.SourceRun = "failed-upgrade"
	o.Run.State = "recovered"
	o.Run.PlanDigest, err = spec.Digest(o.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CompareObservations(o, o, now, time.Hour); err != nil {
		t.Fatalf("legitimate recovery observation rejected: %v", err)
	}
	ordinary := o
	ordinary.Plan.Kind = "Plan"
	ordinary.Plan.SourceRun = ""
	ordinary.Run.PlanDigest, err = spec.Digest(ordinary.Plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := CompareObservations(ordinary, o, now, time.Hour)
	if err != nil || result.Comparable || !contains(result.Reasons, "plan_kind_changed") || result.After.PlanKind != "RecoveryPlan" || result.After.SourceRun != "failed-upgrade" {
		t.Fatal("recovery context lost", err, result)
	}
}
