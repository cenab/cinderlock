package catalog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

type policyTestFixture struct {
	cfg      Config
	plan     StoredRecord
	run      StoredRecord
	approval ApprovalRequest
}

func newPolicyFixture(t *testing.T) (*Store, policyTestFixture) {
	t.Helper()
	store, err := Open(context.Background(), "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store, policyFixture(t, store, "plant")
}

func policyFixture(t *testing.T, store *Store, project string) policyTestFixture {
	t.Helper()
	now := time.Now().UTC()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := spec.TrustPolicy{Header: spec.NewHeader("TrustPolicy"), Spec: spec.TrustSpec{Epoch: 1, Keys: []spec.TrustedKey{{ID: "vendor", PublicKey: base64.StdEncoding.EncodeToString(pub), Applications: []string{"document-qa"}, Channels: []string{"stable"}}}, AllowedActions: []string{"helm"}}}
	trustDigest, err := spec.Digest(trust)
	if err != nil {
		t.Fatal(err)
	}
	site := spec.Site{Header: spec.NewHeader("Site"), Spec: spec.SiteSpec{Profile: "cpu-lab"}}
	site.Metadata.Name = "west"
	siteDigest, err := spec.Digest(site)
	if err != nil {
		t.Fatal(err)
	}
	plan := spec.Plan{Header: spec.NewHeader("Plan"), BundleDigest: spec.Hash([]byte("release-1")), SiteDigest: siteDigest, PolicyDigest: trustDigest, PolicyEpoch: 1, Snapshot: spec.TargetSnapshot{SiteID: "west", TargetID: "target-west"}, Operations: []spec.Operation{{ID: "deploy", Type: "helm"}}, Checks: []spec.Check{{ID: "query", Type: "http", Domain: "workflow", URL: "http://qa/query", ExpectedStatus: 200}}, RequiredChecks: []string{"query"}, Executable: true}
	plan.Metadata = spec.Metadata{Application: "document-qa", Version: "1"}
	planDigest, err := spec.Digest(plan)
	if err != nil {
		t.Fatal(err)
	}
	run := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "run-1", PlanDigest: planDigest, BundleDigest: plan.BundleDigest, SiteID: "west", TargetID: "target-west", State: "succeeded", Acceptance: "pass", StartedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), FinishedAt: now.Format(time.RFC3339Nano), Checks: []spec.CheckResult{{ID: "query", Domain: "workflow", Required: true, Status: "pass"}}}
	run.Metadata = plan.Metadata
	fixture := policyTestFixture{cfg: Config{Store: store, Now: func() time.Time { return now }, Actors: []Actor{
		{ID: "approver", TokenHash: TokenHash("approver-token"), Projects: map[string][]string{project: {"approver"}}, Sites: []string{"west"}},
		{ID: "policy-owner", TokenHash: TokenHash("policy-token"), Projects: map[string][]string{project: {"policy"}}},
		{ID: "operator", TokenHash: TokenHash("operator-token"), Projects: map[string][]string{project: {"operator"}}, Sites: []string{"west"}},
		{ID: "support", TokenHash: TokenHash("support-token"), Projects: map[string][]string{project: {"support"}}, Sites: []string{"west"}},
	}}}
	for _, record := range []struct {
		kind string
		body any
	}{{"TrustPolicy", trust}, {"Site", site}, {"Plan", plan}, {"RunResult", run}} {
		stored := putPolicyRecord(t, store, project, "west", record.kind, record.body)
		if record.kind == "Plan" {
			fixture.plan = stored
		}
		if record.kind == "RunResult" {
			fixture.run = stored
		}
	}
	fixture.approval = ApprovalRequest{Project: project, Site: "west", PlanRecordDigest: fixture.plan.Digest, PlanDigest: planDigest, PolicyDigest: trustDigest, PolicyEpoch: 1, TargetID: "target-west", Actions: []string{"helm"}, ExpiresAt: now.Add(2 * time.Hour).Format(time.RFC3339Nano)}
	return fixture
}

func putPolicyRecord(t *testing.T, store *Store, project, site, kind string, body any) StoredRecord {
	t.Helper()
	data, err := spec.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Put(context.Background(), "fixture", Record{Project: project, Site: site, Kind: kind, Body: data})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func fixturePolicyPack(now time.Time) PolicyPack {
	return PolicyPack{APIVersion: spec.APIVersion, Kind: "PolicyPack", SchemaVersion: 1, ID: "release-policy", ExpiresAt: now.Add(time.Hour).UTC().Format(time.RFC3339Nano), Profiles: []string{"cpu-lab"}, Actions: []string{"helm"}, RequiredChecks: []string{"query"}}
}

func policyHandler(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func policyPath(fixture policyTestFixture, withRun bool) string {
	query := url.Values{"project": {fixture.approval.Project}, "site": {"west"}, "plan": {fixture.plan.Digest}}
	if withRun {
		query.Set("run", fixture.run.Digest)
	}
	return "/api/v1/policy-evaluations?" + query.Encode()
}

func readPolicyEvaluation(t *testing.T, h http.Handler, path string) PolicyEvaluation {
	t.Helper()
	response := request(h, http.MethodGet, path, "approver-token", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("policy evaluation unavailable: %d %s", response.Code, response.Body.String())
	}
	var result PolicyEvaluation
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPolicyPackRegistrationCannotSelfAdmitAndRestrictionsDenyApproval(t *testing.T) {
	store, fixture := newPolicyFixture(t)
	pack := fixturePolicyPack(fixture.cfg.Now())
	pack.Actions = []string{"job"}
	data, err := spec.Canonical(pack)
	if err != nil {
		t.Fatal(err)
	}
	input := Record{Project: "plant", Kind: "PolicyPack", Body: data}
	unconfigured := policyHandler(t, fixture.cfg)
	if response := request(unconfigured, http.MethodPost, "/api/v1/records", "operator-token", "operator-pack", input); response.Code != http.StatusForbidden {
		t.Fatal("operator registered policy pack", response.Code)
	}
	response := request(unconfigured, http.MethodPost, "/api/v1/records", "policy-token", "register-pack", input)
	if response.Code != http.StatusOK {
		t.Fatal("policy administrator cannot register inert pack", response.Code, response.Body.String())
	}
	var registered StoredRecord
	if err = json.Unmarshal(response.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	if result := readPolicyEvaluation(t, unconfigured, policyPath(fixture, false)); result.Configured || len(result.Packs) != 0 {
		t.Fatal("record registration admitted its own restrictions", result)
	}
	fixture.cfg.PolicyPacks = []PolicyPackAdmission{{Project: "plant", Digest: registered.Digest}}
	h := policyHandler(t, fixture.cfg)
	result := readPolicyEvaluation(t, h, policyPath(fixture, false))
	if !result.Configured || result.Satisfied || len(result.Packs) != 1 || !contains(result.Packs[0].Findings, "action_not_permitted:deploy") {
		t.Fatal("restrictive action pack did not deny exact plan", result)
	}
	fixture.approval.CatalogPolicyDigest = result.CatalogPolicyDigest
	response = request(h, http.MethodPost, "/api/v1/approvals", "approver-token", "denied-plan", fixture.approval)
	if response.Code != http.StatusConflict {
		t.Fatalf("policy-denied plan received approval: %d %s", response.Code, response.Body.String())
	}
	approvals, err := store.List(context.Background(), "plant", "west", "Approval")
	if err != nil || len(approvals) != 0 {
		t.Fatal("denied policy review created an approval", err, approvals)
	}
}

func TestPolicyPackExpiryCannotReplayApproval(t *testing.T) {
	store, fixture := newPolicyFixture(t)
	now := fixture.cfg.Now()
	pack := putPolicyRecord(t, store, "plant", "west", "PolicyPack", fixturePolicyPack(now))
	fixture.cfg.Now = func() time.Time { return now }
	fixture.cfg.PolicyPacks = []PolicyPackAdmission{{Project: "plant", Site: "west", Digest: pack.Digest}}
	h := policyHandler(t, fixture.cfg)
	result := readPolicyEvaluation(t, h, policyPath(fixture, true))
	if !result.Satisfied || result.PlanDigest != fixture.approval.PlanDigest || result.RunRecordDigest != fixture.run.Digest {
		t.Fatal("exact admitted scope failed", result)
	}
	fixture.approval.CatalogPolicyDigest = result.CatalogPolicyDigest
	if response := request(h, http.MethodPost, "/api/v1/approvals", "approver-token", "approve", fixture.approval); response.Code != http.StatusOK {
		t.Fatal("eligible plan rejected", response.Code, response.Body.String())
	}
	now = now.Add(time.Hour)
	result = readPolicyEvaluation(t, h, policyPath(fixture, false))
	if result.Satisfied || !contains(result.Packs[0].Findings, "policy_pack_expired") {
		t.Fatal("expired restriction remained satisfied", result)
	}
	for _, key := range []string{"approve", "approve-expired"} {
		if response := request(h, http.MethodPost, "/api/v1/approvals", "approver-token", key, fixture.approval); response.Code != http.StatusConflict {
			t.Fatal("expired policy approved or replayed prior approval", key, response.Code)
		}
	}
}

func TestPolicyPackPacketRequiresExplicitKindAndPolicyRole(t *testing.T) {
	store, fixture := newPolicyFixture(t)
	packet, keys, private := testPacket(t, 1)
	var body PacketBody
	if err := spec.Decode(packet.Body, &body); err != nil {
		t.Fatal(err)
	}
	pack, err := spec.Canonical(fixturePolicyPack(fixture.cfg.Now()))
	if err != nil {
		t.Fatal(err)
	}
	body.Records = []Record{{Project: "plant", Site: "west", Kind: "PolicyPack", Body: pack}}
	packet, err = SignPacket(body, "customer", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = VerifyPacket(packet, keys); err == nil {
		t.Fatal("generic observation key admitted policy pack without explicit kind scope")
	}
	keys[0].Kinds = []string{"PolicyPack"}
	if _, _, err = VerifyPacket(packet, keys); err != nil {
		t.Fatal(err)
	}
	fixture.cfg.PacketKeys = keys
	h := policyHandler(t, fixture.cfg)
	if response := request(h, http.MethodPost, "/api/v1/import-previews", "operator-token", "operator-policy-packet", packet); response.Code != http.StatusForbidden {
		t.Fatal("operator without policy role previewed policy import", response.Code)
	}
	records, err := store.List(context.Background(), "plant", "west", "PolicyPack")
	if err != nil || len(records) != 0 {
		t.Fatal("rejected packet published a policy pack", err)
	}
	fixture.cfg.Actors[2].Projects["plant"] = []string{"operator", "policy"}
	h = policyHandler(t, fixture.cfg)
	response := request(h, http.MethodPost, "/api/v1/import-previews", "operator-token", "authorized-policy-packet", packet)
	if response.Code != http.StatusOK {
		t.Fatal("scoped policy packet could not be reviewed", response.Code, response.Body.String())
	}
	var preview Preview
	if err = json.Unmarshal(response.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	response = request(h, http.MethodPost, "/api/v1/imports", "operator-token", "import-policy-packet", map[string]string{"preview": preview.Digest})
	if response.Code != http.StatusOK {
		t.Fatal("reviewed policy packet could not be imported", response.Code, response.Body.String())
	}
	if result := readPolicyEvaluation(t, h, policyPath(fixture, false)); result.Configured || len(result.Packs) != 0 {
		t.Fatal("packet import independently admitted its own pack", result)
	}
}

func TestPolicyPackEvaluatesExactRequiredCheckContract(t *testing.T) {
	tests := []struct {
		name    string
		pack    func(*PolicyPack)
		change  func(*Observation)
		withRun bool
		finding string
		status  int
	}{
		{name: "required-by-id", withRun: true},
		{name: "required-by-flag", withRun: true, change: func(o *Observation) { o.Plan.RequiredChecks = nil; o.Plan.Checks[0].Required = true }},
		{name: "bound-recovery-plan", withRun: true, change: func(o *Observation) {
			o.Plan.Kind = "RecoveryPlan"
			o.Plan.SourceRun = "failed-upgrade"
			o.Run.SourceRun = o.Plan.SourceRun
		}},
		{name: "unknown-profile", pack: func(p *PolicyPack) { p.Profiles = []string{"other-profile"} }, finding: "profile_not_permitted"},
		{name: "missing-required-check", pack: func(p *PolicyPack) { p.RequiredChecks = []string{"not-declared"} }, finding: "required_check_missing:not-declared"},
		{name: "optional-check", change: func(o *Observation) { o.Plan.RequiredChecks = nil; o.Run.Checks[0].Required = false }, finding: "required_check_missing:query"},
		{name: "failed-run-check", withRun: true, change: func(o *Observation) { o.Run.Checks[0].Status = "fail" }, finding: "required_check_not_passed:query"},
		{name: "unrecorded-run-check", withRun: true, change: func(o *Observation) { o.Run.Checks = nil }, finding: "required_check_not_passed:query"},
		{name: "unsupported-plan-action", change: func(o *Observation) { o.Plan.Operations[0].Type = "execute-arbitrary" }, status: http.StatusBadRequest},
		{name: "unsupported-plan-check", change: func(o *Observation) { o.Plan.Checks[0].Type = "execute-arbitrary" }, status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, fixture := newPolicyFixture(t)
			pack := fixturePolicyPack(fixture.cfg.Now())
			if test.pack != nil {
				test.pack(&pack)
			}
			if test.change != nil {
				o, err := store.Observation(context.Background(), "plant", "west", fixture.run.Digest)
				if err != nil {
					t.Fatal(err)
				}
				test.change(&o)
				o.Run.PlanDigest, err = spec.Digest(o.Plan)
				if err != nil {
					t.Fatal(err)
				}
				fixture.plan = putPolicyRecord(t, store, "plant", "west", "Plan", o.Plan)
				fixture.run = putPolicyRecord(t, store, "plant", "west", "RunResult", o.Run)
			}
			stored := putPolicyRecord(t, store, "plant", "west", "PolicyPack", pack)
			fixture.cfg.PolicyPacks = []PolicyPackAdmission{{Project: "plant", Site: "west", Digest: stored.Digest}}
			h := policyHandler(t, fixture.cfg)
			if test.status != 0 {
				if response := request(h, http.MethodGet, policyPath(fixture, test.withRun), "approver-token", "", nil); response.Code != test.status {
					t.Fatal("unsupported contract evaluated", response.Code)
				}
				return
			}
			result := readPolicyEvaluation(t, h, policyPath(fixture, test.withRun))
			if result.Satisfied != (test.finding == "") || len(result.Packs) != 1 || test.finding != "" && !contains(result.Packs[0].Findings, test.finding) {
				t.Fatal("wrong restriction result", result)
			}
			original, err := store.Get(context.Background(), "plant", "west", "RunResult", fixture.run.Digest)
			if err != nil || string(original.Record.Body) != string(fixture.run.Record.Body) {
				t.Fatal("policy evaluation changed recorded acceptance", err)
			}
		})
	}
}

func TestPolicyPackScopeDependenciesAndStoredIntegrity(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *Store, *policyTestFixture, *PolicyPackAdmission, url.Values)
		status int
	}{
		{name: "other-project", status: http.StatusForbidden, change: func(_ *testing.T, _ *Store, _ *policyTestFixture, _ *PolicyPackAdmission, q url.Values) {
			q.Set("project", "other")
		}},
		{name: "other-site", status: http.StatusForbidden, change: func(_ *testing.T, _ *Store, _ *policyTestFixture, _ *PolicyPackAdmission, q url.Values) {
			q.Set("site", "east")
		}},
		{name: "missing-site", status: http.StatusBadRequest, change: func(_ *testing.T, _ *Store, _ *policyTestFixture, _ *PolicyPackAdmission, q url.Values) {
			q.Del("site")
		}},
		{name: "missing-pack", status: http.StatusNotFound, change: func(_ *testing.T, _ *Store, _ *policyTestFixture, a *PolicyPackAdmission, _ url.Values) {
			a.Digest = spec.Hash([]byte("not-admitted"))
		}},
		{name: "site-pack-is-not-project-pack", status: http.StatusNotFound, change: func(t *testing.T, store *Store, f *policyTestFixture, a *PolicyPackAdmission, _ url.Values) {
			other := putPolicyRecord(t, store, "plant", "east", "PolicyPack", fixturePolicyPack(f.cfg.Now()))
			a.Digest = other.Digest
		}},
		{name: "pack-in-another-project", status: http.StatusNotFound, change: func(t *testing.T, store *Store, f *policyTestFixture, a *PolicyPackAdmission, _ url.Values) {
			other := putPolicyRecord(t, store, "other", "", "PolicyPack", fixturePolicyPack(f.cfg.Now()))
			a.Digest = other.Digest
		}},
		{name: "missing-exact-site", status: http.StatusNotFound, change: func(t *testing.T, store *Store, _ *policyTestFixture, _ *PolicyPackAdmission, _ url.Values) {
			if _, err := store.db.Exec(`DELETE FROM catalog_records WHERE kind='Site'`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "tampered-pack", status: http.StatusBadRequest, change: func(t *testing.T, store *Store, _ *policyTestFixture, _ *PolicyPackAdmission, _ url.Values) {
			if _, err := store.db.Exec(`UPDATE catalog_records SET body=? WHERE kind='PolicyPack'`, []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "tampered-plan", status: http.StatusBadRequest, change: func(t *testing.T, store *Store, _ *policyTestFixture, _ *PolicyPackAdmission, _ url.Values) {
			if _, err := store.db.Exec(`UPDATE catalog_records SET body=? WHERE kind='Plan'`, []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "run-from-another-plan", status: http.StatusBadRequest, change: func(t *testing.T, store *Store, _ *policyTestFixture, _ *PolicyPackAdmission, q url.Values) {
			other := storeComparisonRun(t, store, "cpu-lab", "2", time.Now().UTC(), []spec.CheckResult{{ID: "query", Domain: "workflow", Required: true, Status: "pass"}})
			q.Set("run", other.Digest)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, fixture := newPolicyFixture(t)
			pack := putPolicyRecord(t, store, "plant", "", "PolicyPack", fixturePolicyPack(fixture.cfg.Now()))
			admission := PolicyPackAdmission{Project: "plant", Digest: pack.Digest}
			path, err := url.Parse(policyPath(fixture, true))
			if err != nil {
				t.Fatal(err)
			}
			query := path.Query()
			test.change(t, store, &fixture, &admission, query)
			fixture.cfg.PolicyPacks = []PolicyPackAdmission{admission}
			h := policyHandler(t, fixture.cfg)
			if response := request(h, http.MethodGet, path.Path+"?"+query.Encode(), "approver-token", "", nil); response.Code != test.status {
				t.Fatalf("invalid policy scope evaluated: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestPolicyPackConfigurationChangesInvalidateReviewAndImportPreview(t *testing.T) {
	store, fixture := newPolicyFixture(t)
	pack := putPolicyRecord(t, store, "plant", "", "PolicyPack", fixturePolicyPack(fixture.cfg.Now()))
	fixture.cfg.PolicyPacks = []PolicyPackAdmission{{Project: "plant", Digest: pack.Digest}}
	packet, keys, _ := testPacket(t, 1)
	fixture.cfg.PacketKeys = keys
	h := policyHandler(t, fixture.cfg)
	result := readPolicyEvaluation(t, h, policyPath(fixture, false))
	fixture.approval.CatalogPolicyDigest = result.CatalogPolicyDigest
	response := request(h, http.MethodPost, "/api/v1/import-previews", "operator-token", "preview", packet)
	if response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	var preview Preview
	if err := json.Unmarshal(response.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	fixture.cfg.PolicyPacks[0].Digest = spec.Hash([]byte("missing-independent-admission"))
	if current := readPolicyEvaluation(t, h, policyPath(fixture, false)); !current.Satisfied || current.CatalogPolicyDigest != result.CatalogPolicyDigest {
		t.Fatal("caller mutated the handler's admitted policy snapshot", current)
	}
	changed := policyHandler(t, fixture.cfg)
	if response = request(changed, http.MethodPost, "/api/v1/approvals", "approver-token", "stale-review", fixture.approval); response.Code != http.StatusConflict {
		t.Fatal("changed catalog policy accepted stale plan review", response.Code)
	}
	if response = request(changed, http.MethodPost, "/api/v1/imports", "operator-token", "stale-import", map[string]string{"preview": preview.Digest}); response.Code != http.StatusConflict {
		t.Fatal("changed policy admitted prior import preview", response.Code)
	}
	if response = request(h, http.MethodGet, policyPath(fixture, false), "support-token", "", nil); response.Code != http.StatusForbidden {
		t.Fatal("support-only identity read raw policy scope", response.Code)
	}
}

func TestPolicyPacksIntersectProjectAndSiteRestrictions(t *testing.T) {
	store, fixture := newPolicyFixture(t)
	projectPack := putPolicyRecord(t, store, "plant", "", "PolicyPack", fixturePolicyPack(fixture.cfg.Now()))
	denial := fixturePolicyPack(fixture.cfg.Now())
	denial.ID = "site-restriction"
	denial.Profiles = []string{"other-profile"}
	sitePack := putPolicyRecord(t, store, "plant", "west", "PolicyPack", denial)
	fixture.cfg.PolicyPacks = []PolicyPackAdmission{{Project: "plant", Digest: projectPack.Digest}, {Project: "plant", Site: "west", Digest: sitePack.Digest}}
	result := readPolicyEvaluation(t, policyHandler(t, fixture.cfg), policyPath(fixture, true))
	if result.Satisfied || len(result.Packs) != 2 || !result.Packs[0].Satisfied || result.Packs[1].Satisfied || result.Packs[1].Digest != sitePack.Digest {
		t.Fatal("project pack overrode site restriction", result)
	}
}

func TestPolicyPackStrictSchemaAndPrivateConfiguration(t *testing.T) {
	store, fixture := newPolicyFixture(t)
	pack := fixturePolicyPack(fixture.cfg.Now())
	for _, change := range []func(*PolicyPack){
		func(p *PolicyPack) { p.Actions = []string{"unknown-action"} },
		func(p *PolicyPack) { p.RequiredChecks = []string{"query", "query"} },
		func(p *PolicyPack) { p.ExpiresAt = "" },
		func(p *PolicyPack) { p.Profiles = nil; p.Actions = nil; p.RequiredChecks = nil },
	} {
		invalid := pack
		change(&invalid)
		data, err := spec.Canonical(invalid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Put(context.Background(), "policy-owner", Record{Project: "plant", Kind: "PolicyPack", Body: data}); err == nil {
			t.Fatal("invalid policy pack registered", invalid)
		}
	}
	registered := putPolicyRecord(t, store, "plant", "", "PolicyPack", pack)
	var raw map[string]any
	if err := json.Unmarshal(registered.Record.Body, &raw); err != nil {
		t.Fatal(err)
	}
	raw["program"] = "return true"
	unknown, err := spec.Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Put(context.Background(), "policy-owner", Record{Project: "plant", Kind: "PolicyPack", Body: unknown}); err == nil {
		t.Fatal("policy pack admitted executable or unknown field")
	}
	path := filepath.Join(t.TempDir(), "catalog.json")
	file := FileConfig{APIVersion: spec.APIVersion, Kind: "CatalogConfig", Actors: fixture.cfg.Actors, PolicyPacks: []PolicyPackAdmission{{Project: "plant", Digest: registered.Digest}}}
	if err := spec.Write(path, file); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(context.Background(), path, store)
	if err != nil {
		t.Fatal(err)
	}
	if result := readPolicyEvaluation(t, policyHandler(t, cfg), policyPath(fixture, false)); !result.Configured || !result.Satisfied {
		t.Fatal("private configuration did not independently admit exact pack", result)
	}
}

func TestPostgresPolicyPackEvaluationAndApproval(t *testing.T) {
	dsn := os.Getenv("CINDERLOCK_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CINDERLOCK_TEST_POSTGRES_DSN not set; live policy evaluation not exercised")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal("PostgreSQL catalog unavailable")
	}
	defer store.Close()
	project := fmt.Sprintf("policy-%d", time.Now().UnixNano())
	fixture := policyFixture(t, store, project)
	pack := putPolicyRecord(t, store, project, "", "PolicyPack", fixturePolicyPack(fixture.cfg.Now()))
	fixture.cfg.PolicyPacks = []PolicyPackAdmission{{Project: project, Digest: pack.Digest}}
	h := policyHandler(t, fixture.cfg)
	result := readPolicyEvaluation(t, h, policyPath(fixture, true))
	if !result.Satisfied || !result.Configured {
		t.Fatal("PostgreSQL policy evaluation failed", result)
	}
	fixture.approval.CatalogPolicyDigest = result.CatalogPolicyDigest
	response := request(h, http.MethodPost, "/api/v1/approvals", "approver-token", "approve", fixture.approval)
	if response.Code != http.StatusOK {
		t.Fatal("PostgreSQL policy-bound approval failed", response.Code, response.Body.String())
	}
}
