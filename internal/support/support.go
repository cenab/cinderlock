package support

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cenab/cinderlock/internal/spec"
)

// Summary deliberately excludes target names, raw errors, logs, evidence paths and customer data.
type Summary struct {
	APIVersion   string            `json:"apiVersion"`
	Kind         string            `json:"kind"`
	Application  string            `json:"application,omitempty"`
	Version      string            `json:"version,omitempty"`
	RunID        string            `json:"runID"`
	PlanDigest   string            `json:"planDigest"`
	BundleDigest string            `json:"bundleDigest"`
	State        string            `json:"state"`
	Acceptance   string            `json:"acceptance"`
	Domains      map[string]string `json:"domains"`
	Checks       []CheckSummary    `json:"checks"`
	Steps        []StepSummary     `json:"steps"`
	FindingCodes []string          `json:"findingCodes"`
	Coverage     []string          `json:"coverage"`
}

type CheckSummary struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	Required bool   `json:"required"`
	Status   string `json:"status"`
}
type StepSummary struct {
	ID      string `json:"id"`
	Attempt int    `json:"attempt"`
	Status  string `json:"status"`
}
type Preview struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Digest     string   `json:"digest"`
	Summary    Summary  `json:"summary"`
	Excluded   []string `json:"excluded"`
}

func Summarize(run spec.RunResult) Summary {
	s := Summary{APIVersion: spec.APIVersion, Kind: "SupportSummary", Application: run.Metadata.Application, Version: run.Metadata.Version, RunID: run.RunID, PlanDigest: run.PlanDigest, BundleDigest: run.BundleDigest, State: run.State, Acceptance: run.Acceptance, Domains: map[string]string{}, Checks: []CheckSummary{}, Steps: []StepSummary{}, FindingCodes: []string{}, Coverage: []string{}}
	for _, domain := range []string{"integrity", "readiness", "workflow", "recovery"} {
		status := run.Domains[domain]
		switch status {
		case "pass", "fail", "blocked", "not_tested":
		default:
			status = "not_tested"
		}
		s.Domains[domain] = status
	}
	for _, c := range run.Checks {
		s.Checks = append(s.Checks, CheckSummary{ID: c.ID, Domain: c.Domain, Required: c.Required, Status: c.Status})
	}
	for _, step := range run.Steps {
		s.Steps = append(s.Steps, StepSummary{ID: step.ID, Attempt: step.Attempt, Status: step.Status})
	}
	seen := map[string]bool{}
	for _, f := range run.Findings {
		if !seen[f.Code] {
			s.FindingCodes = append(s.FindingCodes, f.Code)
			seen[f.Code] = true
		}
	}
	sort.Strings(s.FindingCodes)
	if run.RecoveryCoverage == "" {
		s.Coverage = append(s.Coverage, "recovery scope not supplied")
	} else {
		s.Coverage = append(s.Coverage, "recovery scope retained locally")
	}
	if run.OfflineCoverage == "" {
		s.Coverage = append(s.Coverage, "offline scope not supplied")
	} else {
		s.Coverage = append(s.Coverage, "offline scope retained locally")
	}
	return s
}

func Collect(run spec.RunResult) (Preview, error) {
	if err := spec.ValidateHeader(run.Header, "RunResult"); err != nil {
		return Preview{}, err
	}
	if run.RunID == "" {
		return Preview{}, errors.New("run identity required")
	}
	s := Summarize(run)
	digest, err := spec.Digest(s)
	if err != nil {
		return Preview{}, err
	}
	return Preview{APIVersion: spec.APIVersion, Kind: "SupportExportPreview", Digest: digest, Summary: s, Excluded: []string{"site and target identities", "raw errors and finding messages", "evidence paths and attachments", "logs, prompts and documents", "secret values and configuration", "detailed coverage topology"}}, nil
}

func Export(preview Preview, approvedDigest, path string) error {
	if preview.APIVersion != spec.APIVersion || preview.Kind != "SupportExportPreview" {
		return errors.New("unsupported support preview")
	}
	digest, err := spec.Digest(preview.Summary)
	if err != nil {
		return err
	}
	if digest != preview.Digest || digest != approvedDigest {
		return errors.New("support preview changed or approved digest does not match")
	}
	if preview.Summary.Kind != "SupportSummary" || preview.Summary.APIVersion != spec.APIVersion {
		return fmt.Errorf("invalid support summary")
	}
	return spec.Write(path, preview.Summary)
}
