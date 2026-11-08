package catalog

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

// Observation binds a recorded result to the exact plan and site that described
// its checks. Catalog admission does not independently attest those observations.
type Observation struct {
	Run  spec.RunResult `json:"run"`
	Plan spec.Plan      `json:"plan"`
	Site spec.Site      `json:"site"`
}

type EvidenceSubject struct {
	RunID           string `json:"runID"`
	PlanDigest      string `json:"planDigest"`
	Application     string `json:"application"`
	BundleDigest    string `json:"bundleDigest"`
	TargetID        string `json:"targetID"`
	Profile         string `json:"profile"`
	TestScopeDigest string `json:"testScopeDigest"`
}

type ComparisonSide struct {
	RunID      string          `json:"runID"`
	Version    string          `json:"version"`
	Subject    EvidenceSubject `json:"subject"`
	ObservedAt string          `json:"observedAt"`
	Freshness  string          `json:"freshness"`
	Acceptance string          `json:"recordedAcceptance"`
	PlanKind   string          `json:"planKind"`
	SourceRun  string          `json:"sourceRun,omitempty"`
}
type ResultChange struct {
	ID     string `json:"id"`
	Change string `json:"change"`
	Before string `json:"before"`
	After  string `json:"after"`
}
type RunComparison struct {
	APIVersion       string         `json:"apiVersion"`
	Kind             string         `json:"kind"`
	Comparable       bool           `json:"comparable"`
	Reasons          []string       `json:"reasons"`
	Before           ComparisonSide `json:"before"`
	After            ComparisonSide `json:"after"`
	Checks           []ResultChange `json:"checks"`
	Domains          []ResultChange `json:"domains"`
	FreshnessSeconds int64          `json:"freshnessSeconds"`
	Notice           string         `json:"notice"`
}

// SubjectForObservation derives an evidence subject only after the stored run,
// exact plan, effective check contract, and site have been bound together.
func SubjectForObservation(o Observation) (EvidenceSubject, error) {
	var out EvidenceSubject
	if o.Plan.Kind != "Plan" && o.Plan.Kind != "RecoveryPlan" {
		return out, errors.New("unsupported recorded plan kind")
	}
	for _, header := range []struct {
		header spec.Header
		kind   string
	}{{o.Run.Header, "RunResult"}, {o.Plan.Header, o.Plan.Kind}, {o.Site.Header, "Site"}} {
		if err := spec.ValidateHeader(header.header, header.kind); err != nil {
			return out, err
		}
	}
	planDigest, err := spec.Digest(o.Plan)
	if err != nil {
		return out, err
	}
	siteDigest, err := spec.Digest(o.Site)
	if err != nil {
		return out, err
	}
	if !spec.ValidDigest(o.Run.BundleDigest) || o.Run.PlanDigest != planDigest || o.Run.BundleDigest != o.Plan.BundleDigest || o.Plan.SiteDigest != siteDigest {
		return out, errors.New("run, plan, bundle, and site identities do not match")
	}
	if o.Run.RunID == "" || o.Run.SiteID == "" || o.Run.TargetID == "" || o.Run.TargetID != o.Plan.Snapshot.TargetID || o.Run.SiteID != o.Site.Metadata.Name || o.Run.SiteID != o.Plan.Snapshot.SiteID || o.Run.Metadata.Application == "" || o.Run.Metadata.Application != o.Plan.Metadata.Application || o.Run.Metadata.Version == "" || o.Run.Metadata.Version != o.Plan.Metadata.Version || o.Site.Spec.Profile == "" {
		return out, errors.New("run subject, application, version, target, or profile is unbound")
	}
	checks := append([]spec.Check(nil), o.Plan.Checks...)
	if len(checks) == 0 || len(checks) > 128 {
		return out, errors.New("comparison needs a bounded declared check contract")
	}
	declared := map[string]spec.Check{}
	for _, c := range checks {
		if !identifier.MatchString(c.ID) || declared[c.ID].ID != "" {
			return out, errors.New("duplicate or invalid declared check")
		}
		declared[c.ID] = c
	}
	requiredIDs := map[string]bool{}
	for _, id := range o.Plan.RequiredChecks {
		if _, ok := declared[id]; !ok || requiredIDs[id] {
			return out, errors.New("required check ID is missing or duplicated")
		}
		requiredIDs[id] = true
	}
	seen := map[string]bool{}
	for _, c := range o.Run.Checks {
		d, ok := declared[c.ID]
		if !ok || seen[c.ID] || c.Domain != d.Domain || c.Required != (d.Required || requiredIDs[c.ID]) {
			return out, errors.New("run check is duplicated or differs from its declared contract")
		}
		seen[c.ID] = true
	}
	required := append([]string(nil), o.Plan.RequiredChecks...)
	sort.Slice(checks, func(i, j int) bool { return checks[i].ID < checks[j].ID })
	sort.Strings(required)
	scope, err := spec.Digest(struct {
		Checks   []spec.Check `json:"checks"`
		Required []string     `json:"required"`
	}{checks, required})
	if err != nil {
		return out, err
	}
	return EvidenceSubject{RunID: o.Run.RunID, PlanDigest: o.Run.PlanDigest, Application: o.Run.Metadata.Application, BundleDigest: o.Run.BundleDigest, TargetID: o.Run.TargetID, Profile: o.Site.Spec.Profile, TestScopeDigest: scope}, nil
}

func comparisonSide(o Observation, subject EvidenceSubject, now time.Time, maxAge time.Duration) ComparisonSide {
	at := o.Run.FinishedAt
	if at == "" {
		at = o.Run.StartedAt
	}
	freshness := "time_unknown"
	if timestamp, err := time.Parse(time.RFC3339Nano, at); err == nil {
		switch {
		case timestamp.After(now):
			freshness = "future_observation"
		case now.Sub(timestamp) > maxAge:
			freshness = "stale"
		default:
			freshness = "recent_observation"
		}
	}
	return ComparisonSide{RunID: o.Run.RunID, Version: o.Run.Metadata.Version, Subject: subject, ObservedAt: at, Freshness: freshness, Acceptance: o.Run.Acceptance, PlanKind: o.Plan.Kind, SourceRun: o.Plan.SourceRun}
}

// CompareObservations never combines acceptance or upgrades old observations to
// current health. Changes of coverage remain visible but are not comparable.
func CompareObservations(before, after Observation, now time.Time, maxAge time.Duration) (RunComparison, error) {
	out := RunComparison{APIVersion: spec.APIVersion, Kind: "RunComparison", Comparable: true, Reasons: []string{}, Checks: []ResultChange{}, Domains: []ResultChange{}, Notice: "Stored observations only, never live cluster health. Acceptance is retained separately for each exact release and test scope."}
	if maxAge <= 0 || maxAge > 365*24*time.Hour {
		return out, errors.New("freshness interval must be positive and at most one year")
	}
	a, err := SubjectForObservation(before)
	if err != nil {
		return out, fmt.Errorf("baseline: %w", err)
	}
	b, err := SubjectForObservation(after)
	if err != nil {
		return out, fmt.Errorf("candidate: %w", err)
	}
	if a.Application != b.Application || a.TargetID != b.TargetID {
		return out, errors.New("cannot compare another application or target")
	}
	out.Before = comparisonSide(before, a, now, maxAge)
	out.After = comparisonSide(after, b, now, maxAge)
	out.FreshnessSeconds = int64(maxAge / time.Second)
	if before.Plan.Kind != after.Plan.Kind {
		out.Comparable = false
		out.Reasons = append(out.Reasons, "plan_kind_changed")
	}
	if a.Profile != b.Profile {
		out.Comparable = false
		out.Reasons = append(out.Reasons, "profile_changed")
	}
	if a.TestScopeDigest != b.TestScopeDigest {
		out.Comparable = false
		out.Reasons = append(out.Reasons, "test_scope_changed")
	}
	states := func(o Observation) map[string]string {
		m := map[string]string{}
		for _, c := range o.Plan.Checks {
			m[c.ID] = "not_recorded"
		}
		for _, c := range o.Run.Checks {
			status := c.Status
			if status == "" {
				status = "not_recorded"
			}
			m[c.ID] = status
		}
		return m
	}
	old, new := states(before), states(after)
	ids := map[string]bool{}
	for id := range old {
		ids[id] = true
	}
	for id := range new {
		ids[id] = true
	}
	sorted := []string{}
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		a, aok := old[id]
		b, bok := new[id]
		change := "unchanged"
		switch {
		case !aok:
			change = "new"
		case !bok:
			change = "missing"
		case a != b:
			change = "changed"
		}
		out.Checks = append(out.Checks, ResultChange{ID: id, Change: change, Before: a, After: b})
	}
	for _, domain := range []string{"integrity", "readiness", "workflow", "recovery"} {
		a, b := before.Run.Domains[domain], after.Run.Domains[domain]
		if a == "" {
			a = "not_tested"
		}
		if b == "" {
			b = "not_tested"
		}
		change := "unchanged"
		if a != b {
			change = "changed"
		}
		out.Domains = append(out.Domains, ResultChange{ID: domain, Change: change, Before: a, After: b})
	}
	return out, nil
}

func (s *Store) bodyRecord(ctx context.Context, project, site, kind, digest string) (StoredRecord, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT digest,body,imported_at FROM catalog_records WHERE project=? AND site=? AND kind=? ORDER BY imported_at DESC,digest LIMIT 1000`), project, site, kind)
	if err != nil {
		return StoredRecord{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var record StoredRecord
		var body []byte
		if err = rows.Scan(&record.Digest, &body, &record.ImportedAt); err != nil {
			return StoredRecord{}, err
		}
		if spec.Hash(body) != record.Digest {
			return StoredRecord{}, errors.New("catalog record integrity mismatch")
		}
		if err = strictJSON(body, &record.Record); err != nil {
			return StoredRecord{}, err
		}
		if spec.Hash(record.Record.Body) == digest {
			return record, nil
		}
	}
	if err = rows.Err(); err != nil {
		return StoredRecord{}, err
	}
	return StoredRecord{}, fmt.Errorf("%w: exact linked %s not found in bounded admitted history", ErrNotFound, kind)
}

func (s *Store) Observation(ctx context.Context, project, site, runDigest string) (Observation, error) {
	var o Observation
	if !identifier.MatchString(project) || !identifier.MatchString(site) || !spec.ValidDigest(runDigest) {
		return o, errors.New("explicit project, site, and run record digest required")
	}
	record, err := s.Get(ctx, project, site, "RunResult", runDigest)
	if err != nil {
		return o, err
	}
	if err = strictJSON(record.Record.Body, &o.Run); err != nil {
		return o, err
	}
	plan, err := s.bodyRecord(ctx, project, site, "Plan", o.Run.PlanDigest)
	if err != nil {
		return o, err
	}
	if err = strictJSON(plan.Record.Body, &o.Plan); err != nil {
		return o, err
	}
	target, err := s.bodyRecord(ctx, project, site, "Site", o.Plan.SiteDigest)
	if err != nil {
		return o, err
	}
	if err = strictJSON(target.Record.Body, &o.Site); err != nil {
		return o, err
	}
	_, err = SubjectForObservation(o)
	return o, err
}

func (s *Store) Compare(ctx context.Context, project, site, before, after string, now time.Time, maxAge time.Duration) (RunComparison, error) {
	a, err := s.Observation(ctx, project, site, before)
	if err != nil {
		return RunComparison{}, err
	}
	b, err := s.Observation(ctx, project, site, after)
	if err != nil {
		return RunComparison{}, err
	}
	return CompareObservations(a, b, now, maxAge)
}

func (s *Server) comparison(w http.ResponseWriter, r *http.Request, a Actor) {
	q := r.URL.Query()
	project, site := q.Get("project"), q.Get("site")
	if !a.can(project, site, "read") || onlySupport(a, project) {
		s.fail(w, errDenied)
		return
	}
	if q.Get("before") == "" || q.Get("after") == "" {
		if r.URL.Path != "/comparisons" {
			s.fail(w, errors.New("both exact run digests required"))
			return
		}
		renderComparison(w, nil, project, site, "", "")
		return
	}
	result, err := s.cfg.Store.Compare(r.Context(), project, site, q.Get("before"), q.Get("after"), s.cfg.Now(), 24*time.Hour)
	if err != nil {
		s.fail(w, err)
		return
	}
	if r.URL.Path == "/comparisons" {
		renderComparison(w, &result, project, site, q.Get("before"), q.Get("after"))
		return
	}
	s.json(w, result)
}

func renderComparison(w http.ResponseWriter, result *RunComparison, project, site, beforeDigest, afterDigest string) {
	t, err := template.New("comparison").Parse(comparisonTemplate)
	if err != nil {
		http.Error(w, "template unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.Execute(w, struct {
		Result                    *RunComparison
		Project, Site             string
		BeforeDigest, AfterDigest string
	}{result, project, site, beforeDigest, afterDigest})
}

const comparisonTemplate = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cinderlock recorded run comparison</title><style>body{margin:0;background:#101a1c;color:#edf4f1;font:1rem/1.6 system-ui,sans-serif}main{max-width:76rem;margin:auto;padding:1.5rem}a{color:#8ff0cc}input,button{font:inherit;padding:.5rem;max-width:100%;box-sizing:border-box}label{display:block;margin:1rem 0}input{display:block;width:100%}a:focus-visible,input:focus-visible,button:focus-visible{outline:3px solid white;outline-offset:4px}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #55736b;padding:.7rem;overflow-wrap:anywhere}pre,p,dd{overflow-wrap:anywhere}.record-identity{display:block;white-space:normal;overflow-wrap:anywhere}dd{margin:0 0 1rem}dt{font-weight:bold}@media(max-width:40rem){table,tbody,tr,th,td{display:block}thead{position:absolute;left:-9999px}td:before{content:attr(data-label) ': ';font-weight:bold}}</style></head><body><main><p><a href="/">Local catalog</a></p><h1>Compare recorded runs</h1><p>These are last-known observations. This page does not inspect a cluster or establish live health.</p><form method="get" action="/comparisons"><label>Project<input name="project" value="{{.Project}}" required></label><label>Site<input name="site" value="{{.Site}}" required></label><label>Baseline run record digest<input name="before" value="{{.BeforeDigest}}"{{if .BeforeDigest}} aria-describedby="selected-before-record"{{end}} required></label>{{if .BeforeDigest}}<p>Baseline record in this comparison<code class="record-identity" id="selected-before-record">{{.BeforeDigest}}</code></p>{{end}}<label>Candidate run record digest<input name="after" value="{{.AfterDigest}}"{{if .AfterDigest}} aria-describedby="selected-after-record"{{end}} required></label>{{if .AfterDigest}}<p>Candidate record in this comparison<code class="record-identity" id="selected-after-record">{{.AfterDigest}}</code></p>{{end}}<button type="submit">Compare observations</button></form>{{with .Result}}<h2>Scope</h2><p>Comparable: <strong>{{.Comparable}}</strong></p>{{range .Reasons}}<p>{{.}}</p>{{end}}<p>{{.Notice}}</p><h2>Recorded releases</h2><p>Baseline: {{.Before.RunID}} / {{.Before.Version}} / {{.Before.Freshness}} / recorded acceptance {{.Before.Acceptance}}</p><p>Candidate: {{.After.RunID}} / {{.After.Version}} / {{.After.Freshness}} / recorded acceptance {{.After.Acceptance}}</p><p>Baseline plan kind: {{.Before.PlanKind}}{{if .Before.SourceRun}}; source run: {{.Before.SourceRun}}{{end}}.</p><p>Candidate plan kind: {{.After.PlanKind}}{{if .After.SourceRun}}; source run: {{.After.SourceRun}}{{end}}.</p><p>Application {{.Before.Subject.Application}}; target {{.Before.Subject.TargetID}}. Freshness interval: {{.FreshnessSeconds}} seconds.</p><dl><dt>Baseline profile</dt><dd>{{.Before.Subject.Profile}}</dd><dt>Candidate profile</dt><dd>{{.After.Subject.Profile}}</dd><dt>Baseline bundle</dt><dd>{{.Before.Subject.BundleDigest}}</dd><dt>Candidate bundle</dt><dd>{{.After.Subject.BundleDigest}}</dd><dt>Baseline test scope</dt><dd>{{.Before.Subject.TestScopeDigest}}</dd><dt>Candidate test scope</dt><dd>{{.After.Subject.TestScopeDigest}}</dd><dt>Baseline observed</dt><dd>{{.Before.ObservedAt}}</dd><dt>Candidate observed</dt><dd>{{.After.ObservedAt}}</dd></dl><h2>Check coverage</h2><table><thead><tr><th scope="col">Check</th><th scope="col">Change</th><th scope="col">Baseline</th><th scope="col">Candidate</th></tr></thead><tbody>{{range .Checks}}<tr><th scope="row">{{.ID}}</th><td data-label="Change">{{.Change}}</td><td data-label="Baseline">{{if .Before}}{{.Before}}{{else}}Not in this test scope{{end}}</td><td data-label="Candidate">{{if .After}}{{.After}}{{else}}Not in this test scope{{end}}</td></tr>{{end}}</tbody></table><h2>Result domains</h2><table><thead><tr><th scope="col">Domain</th><th scope="col">Change</th><th scope="col">Baseline</th><th scope="col">Candidate</th></tr></thead><tbody>{{range .Domains}}<tr><th scope="row">{{.ID}}</th><td data-label="Change">{{.Change}}</td><td data-label="Baseline">{{if .Before}}{{.Before}}{{else}}Not in this test scope{{end}}</td><td data-label="Candidate">{{if .After}}{{.After}}{{else}}Not in this test scope{{end}}</td></tr>{{end}}</tbody></table>{{end}}</main></body></html>`
