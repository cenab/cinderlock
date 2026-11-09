package catalog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

// PolicyPack can only restrict catalog review. Its record is inert until its
// exact digest is independently admitted in private catalog configuration.
type PolicyPack struct {
	APIVersion     string   `json:"apiVersion"`
	Kind           string   `json:"kind"`
	SchemaVersion  int      `json:"schemaVersion"`
	ID             string   `json:"id"`
	ExpiresAt      string   `json:"expiresAt"`
	Profiles       []string `json:"profiles,omitempty"`
	Actions        []string `json:"actions,omitempty"`
	RequiredChecks []string `json:"requiredChecks,omitempty"`
}

type PolicyPackAdmission struct {
	Project string `json:"project"`
	Site    string `json:"site,omitempty"`
	Digest  string `json:"digest"`
}

type PolicyPackResult struct {
	ID        string   `json:"id"`
	Digest    string   `json:"digest"`
	Satisfied bool     `json:"satisfied"`
	Findings  []string `json:"findings"`
}

type PolicyEvaluation struct {
	APIVersion          string             `json:"apiVersion"`
	Kind                string             `json:"kind"`
	Project             string             `json:"project"`
	Site                string             `json:"site"`
	PlanRecordDigest    string             `json:"planRecordDigest"`
	PlanDigest          string             `json:"planDigest"`
	RunRecordDigest     string             `json:"runRecordDigest,omitempty"`
	CatalogPolicyDigest string             `json:"catalogPolicyDigest"`
	Configured          bool               `json:"configured"`
	Satisfied           bool               `json:"satisfied"`
	Packs               []PolicyPackResult `json:"packs"`
	Notice              string             `json:"notice"`
}

func policyAction(action string) bool {
	// Packs deliberately cover only ordinary release and recovery operation types.
	return contains([]string{"import", "helm", "job", "migrate", "backup", "reindex", "restart", "seed", "gitops"}, action)
}

func validatePolicyPack(pack PolicyPack) error {
	if pack.APIVersion != spec.APIVersion || pack.Kind != "PolicyPack" || pack.SchemaVersion != 1 || !identifier.MatchString(pack.ID) {
		return errors.New("unsupported typed policy pack or identity")
	}
	if _, err := time.Parse(time.RFC3339Nano, pack.ExpiresAt); err != nil {
		return errors.New("policy pack expiry is required")
	}
	if len(pack.Profiles)+len(pack.Actions)+len(pack.RequiredChecks) == 0 {
		return errors.New("policy pack needs at least one restriction")
	}
	for _, values := range [][]string{pack.Profiles, pack.Actions, pack.RequiredChecks} {
		if len(values) > 128 {
			return errors.New("policy pack restriction exceeds size limit")
		}
		seen := map[string]bool{}
		for _, value := range values {
			if !identifier.MatchString(value) || seen[value] {
				return errors.New("policy pack restriction is invalid or duplicated")
			}
			seen[value] = true
		}
	}
	for _, action := range pack.Actions {
		if !policyAction(action) {
			return errors.New("unsupported policy pack action")
		}
	}
	return nil
}

func validatePolicyAdmissions(admissions []PolicyPackAdmission) error {
	if len(admissions) > 128 {
		return errors.New("policy pack admission exceeds size limit")
	}
	seen := map[PolicyPackAdmission]bool{}
	for _, admission := range admissions {
		if !identifier.MatchString(admission.Project) || admission.Site != "" && !identifier.MatchString(admission.Site) || !spec.ValidDigest(admission.Digest) || seen[admission] {
			return errors.New("policy pack admission needs unique exact project/site/digest scope")
		}
		seen[admission] = true
	}
	return nil
}

func (s *Server) applicablePolicyPacks(project, site string) []PolicyPackAdmission {
	var out []PolicyPackAdmission
	for _, admission := range s.cfg.PolicyPacks {
		if admission.Project == project && (admission.Site == "" || admission.Site == site) {
			out = append(out, admission)
		}
	}
	return out
}

func (s *Store) policyPlan(ctx context.Context, project, site, digest string) (spec.Plan, spec.Site, error) {
	var plan spec.Plan
	var target spec.Site
	if !identifier.MatchString(project) || !identifier.MatchString(site) || !spec.ValidDigest(digest) {
		return plan, target, errors.New("policy evaluation requires an explicit project, site, and exact plan record")
	}
	record, err := s.Get(ctx, project, site, "Plan", digest)
	if err != nil {
		return plan, target, err
	}
	if err = strictJSON(record.Record.Body, &plan); err != nil {
		return plan, target, err
	}
	if !applicationPlanKind(plan.Kind) {
		return plan, target, errors.New("unsupported policy evaluation plan kind")
	}
	if err = spec.ValidateHeader(plan.Header, plan.Kind); err != nil {
		return plan, target, err
	}
	record, err = s.bodyRecord(ctx, project, site, "Site", plan.SiteDigest)
	if err != nil {
		return plan, target, err
	}
	if err = strictJSON(record.Record.Body, &target); err != nil {
		return plan, target, err
	}
	if err = spec.ValidateHeader(target.Header, "Site"); err != nil {
		return plan, target, err
	}
	if target.Metadata.Name != site || plan.Snapshot.SiteID != site || plan.Snapshot.TargetID == "" || !identifier.MatchString(target.Spec.Profile) || plan.Metadata.Application == "" || plan.Metadata.Version == "" || !spec.ValidDigest(plan.BundleDigest) {
		return plan, target, errors.New("policy evaluation plan and site scope is unbound")
	}
	// Adopted-source checks can have no authored operations beyond their checks.
	missingOperations := len(plan.Operations) == 0 && plan.Kind != "GitOpsChecksPlan" && plan.Kind != "GitOpsDataChecksPlan"
	if len(plan.Checks) == 0 || len(plan.Checks) > 128 || missingOperations || len(plan.Operations) > 128 {
		return plan, target, errors.New("policy evaluation requires bounded declared checks and operations")
	}
	checks := map[string]bool{}
	for _, check := range plan.Checks {
		if err = spec.ValidateCheck(check); err != nil {
			return plan, target, err
		}
		if checks[check.ID] {
			return plan, target, errors.New("duplicate policy evaluation check")
		}
		checks[check.ID] = true
	}
	required := map[string]bool{}
	for _, id := range plan.RequiredChecks {
		if !checks[id] || required[id] {
			return plan, target, errors.New("required check is missing or duplicated")
		}
		required[id] = true
	}
	operations := map[string]bool{}
	for _, operation := range plan.Operations {
		if !policyAction(operation.Type) || operations[operation.ID] {
			return plan, target, errors.New("unsupported or duplicate policy evaluation operation")
		}
		if err = spec.ValidateOperation(operation); err != nil {
			return plan, target, err
		}
		operations[operation.ID] = true
	}
	return plan, target, nil
}

func (s *Server) evaluatePolicyPacks(ctx context.Context, project, site, planRecord, runRecord string) (PolicyEvaluation, error) {
	out := PolicyEvaluation{APIVersion: spec.APIVersion, Kind: "PolicyEvaluation", Project: project, Site: site, PlanRecordDigest: planRecord, RunRecordDigest: runRecord, CatalogPolicyDigest: s.policy, Satisfied: true, Packs: []PolicyPackResult{}, Notice: "Catalog restrictions only. This result does not authorize execution, change recorded acceptance, or establish live health."}
	plan, target, err := s.cfg.Store.policyPlan(ctx, project, site, planRecord)
	if err != nil {
		return out, err
	}
	out.PlanDigest, err = spec.Digest(plan)
	if err != nil {
		return out, err
	}
	var run spec.RunResult
	if runRecord != "" {
		observation, err := s.cfg.Store.Observation(ctx, project, site, runRecord)
		if err != nil {
			return out, err
		}
		if observation.Run.PlanDigest != out.PlanDigest {
			return out, errors.New("policy evaluation run differs from the exact selected plan")
		}
		run = observation.Run
	}
	admissions := s.applicablePolicyPacks(project, site)
	out.Configured = len(admissions) > 0
	now := s.cfg.Now()
	for _, admission := range admissions {
		record, err := s.cfg.Store.Get(ctx, project, admission.Site, "PolicyPack", admission.Digest)
		if err != nil {
			return out, err
		}
		var pack PolicyPack
		if err = strictJSON(record.Record.Body, &pack); err != nil {
			return out, err
		}
		if err = validatePolicyPack(pack); err != nil {
			return out, err
		}
		result := PolicyPackResult{ID: pack.ID, Digest: admission.Digest, Satisfied: true, Findings: []string{}}
		expires, _ := time.Parse(time.RFC3339Nano, pack.ExpiresAt)
		if !now.Before(expires) {
			result.Findings = append(result.Findings, "policy_pack_expired")
		}
		if len(pack.Profiles) > 0 && !contains(pack.Profiles, target.Spec.Profile) {
			result.Findings = append(result.Findings, "profile_not_permitted")
		}
		for _, operation := range plan.Operations {
			if len(pack.Actions) > 0 && !contains(pack.Actions, operation.Type) {
				result.Findings = append(result.Findings, "action_not_permitted:"+operation.ID)
			}
		}
		for _, id := range pack.RequiredChecks {
			required := false
			for _, check := range plan.Checks {
				if check.ID == id && (check.Required || contains(plan.RequiredChecks, id)) {
					required = true
				}
			}
			if !required {
				result.Findings = append(result.Findings, "required_check_missing:"+id)
			}
			if runRecord != "" {
				passed := false
				for _, check := range run.Checks {
					if check.ID == id && check.Status == "pass" {
						passed = true
					}
				}
				if !passed {
					result.Findings = append(result.Findings, "required_check_not_passed:"+id)
				}
			}
		}
		result.Satisfied = len(result.Findings) == 0
		out.Satisfied = out.Satisfied && result.Satisfied
		out.Packs = append(out.Packs, result)
	}
	return out, nil
}

func (s *Server) policyEvaluation(w http.ResponseWriter, r *http.Request, actor Actor) {
	query := r.URL.Query()
	project, site := query.Get("project"), query.Get("site")
	if !actor.can(project, site, "read") || onlySupport(actor, project) {
		s.fail(w, errDenied)
		return
	}
	result, err := s.evaluatePolicyPacks(r.Context(), project, site, query.Get("plan"), query.Get("run"))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.json(w, result)
}

func (s *Server) checkPolicyApproval(ctx context.Context, request ApprovalRequest) error {
	if request.CatalogPolicyDigest != "" && request.CatalogPolicyDigest != s.policy {
		return fmt.Errorf("%w: catalog policy changed since review", ErrConflict)
	}
	if len(s.applicablePolicyPacks(request.Project, request.Site)) == 0 {
		return nil
	}
	if request.CatalogPolicyDigest != s.policy {
		return fmt.Errorf("%w: catalog policy changed since review", ErrConflict)
	}
	expires, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil || !s.cfg.Now().Before(expires) {
		return fmt.Errorf("%w: policy review approval expired", ErrConflict)
	}
	result, err := s.evaluatePolicyPacks(ctx, request.Project, request.Site, request.PlanRecordDigest, "")
	if err != nil {
		return err
	}
	if !result.Satisfied {
		return fmt.Errorf("%w: organizational policy restrictions are not satisfied", ErrConflict)
	}
	return nil
}
