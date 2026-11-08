package storageplan

import (
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

func pointer(value int64) *int64 { return &value }

func fixture() Input {
	now := time.Now().UTC()
	input := Input{Profile: Profile, Inventory: spec.StorageInventory{BundleBytes: 20, VerifiedPayloadBytes: 30, ImageCompressedBytes: 20, ModelBytes: 40, LargestModelFileBytes: 25}, Required: []string{"registry", "runtime", "models", "migrations", "indexes", "backups"}, Operator: spec.StorageCapacity{Domain: "operator", Binding: "operator-fs", Source: "local Statfs", AvailableBytes: pointer(1000), RetainedBytes: pointer(50), ObservedAt: now.Format(time.RFC3339Nano), Status: "observed"}, OperatorAdditionalBytes: 4, AllowAssertions: true, BundleDigest: "bundle", SiteDigest: "site", PolicyDigest: "policy", Now: now}
	for _, domain := range Domains {
		budget := spec.StorageBudget{Domain: domain}
		switch domain {
		case "operator":
			budget.AdditionalBytes = 10
			budget.TemporaryBytes = 5
		case "registry":
			budget.AdditionalBytes = 2
			budget.TemporaryBytes = 3
		case "runtime":
			budget.AdditionalBytes = 60
			budget.TemporaryBytes = 10
		case "models":
			budget.TemporaryBytes = 5
		case "indexes":
			budget.AdditionalBytes = 30
			budget.TemporaryBytes = 15
		case "migrations":
			budget.AdditionalBytes = 20
			budget.TemporaryBytes = 10
		case "backups":
			budget.AdditionalBytes = 50
			budget.TemporaryBytes = 5
		}
		input.Budgets = append(input.Budgets, budget)
		if domain != "operator" {
			input.Capacities = append(input.Capacities, spec.StorageCapacity{Domain: domain, Binding: domain + "-pool", Source: "customer capacity observation", AvailableBytes: pointer(1000), RetainedBytes: pointer(100), ObservedAt: now.Format(time.RFC3339Nano), Status: "asserted"})
		}
	}
	return input
}

func TestModelsRetainPriorRevisionAndStageLargestFileWithoutChargingItTwice(t *testing.T) {
	input := fixture()
	for i := range input.Capacities {
		if input.Capacities[i].Domain == "models" {
			input.Capacities[i].AvailableBytes = pointer(70)
		}
	}
	assessment, err := Assess(input)
	if err != nil || !assessment.Executable {
		t.Fatalf("valid storage plan rejected: %#v %v", assessment, err)
	}
	for _, domain := range assessment.Domains {
		if domain.Domain == "models" {
			if domain.AdditionalBytes != 40 || domain.TemporaryBytes != 30 || domain.RetainedBytes != 100 || domain.PeakBytes != 170 || domain.Confidence != "verified_and_asserted" {
				t.Fatalf("model peak loses retained/staging scope: %#v", domain)
			}
			return
		}
	}
	t.Fatal("model storage domain missing")
}

func TestSharedBindingMustFitCombinedDomainPeaks(t *testing.T) {
	input := fixture()
	for i := range input.Capacities {
		capacity := &input.Capacities[i]
		if capacity.Domain == "models" || capacity.Domain == "registry" || capacity.Domain == "runtime" {
			capacity.Binding = "shared-node-pool"
			capacity.AvailableBytes = pointer(100)
		}
	}
	insufficient, err := Assess(input)
	if err != nil || insufficient.Executable {
		t.Fatalf("separate domain checks hid shared exhaustion: %#v %v", insufficient, err)
	}
	found := false
	for _, finding := range insufficient.Findings {
		if finding.Code == "STORAGE_BINDING_INSUFFICIENT" {
			found = true
		}
	}
	if !found {
		t.Fatal("shared capacity prerequisite was not identified")
	}
	for i := range input.Capacities {
		if input.Capacities[i].Binding == "shared-node-pool" {
			input.Capacities[i].AvailableBytes = pointer(200)
		}
	}
	control, err := Assess(input)
	if err != nil || !control.Executable {
		t.Fatalf("sufficient control rejected: %#v %v", control, err)
	}
	for _, binding := range control.Bindings {
		if binding.Binding == "shared-node-pool" {
			if binding.RequiredAdditionalBytes != 165 {
				t.Fatalf("wrong shared requirement: %#v", binding)
			}
			return
		}
	}
	t.Fatal("shared binding missing")
}

func TestUnknownStaleUnsupportedAndOverflowingInputsCannotPass(t *testing.T) {
	for _, scenario := range []string{"no-assertion-permission", "unknown-profile", "missing-budget", "unknown-capacity", "missing-retained", "stale-capacity", "future-capacity", "fake-measured-target", "negative-budget", "overflow", "unknown-domain", "duplicate-capacity"} {
		t.Run(scenario, func(t *testing.T) {
			input := fixture()
			switch scenario {
			case "no-assertion-permission":
				input.AllowAssertions = false
			case "unknown-profile":
				input.Profile = "future-profile"
			case "missing-budget":
				input.Budgets = input.Budgets[1:]
			case "unknown-capacity":
				input.Capacities[0].AvailableBytes = nil
			case "missing-retained":
				input.Capacities[0].RetainedBytes = nil
			case "stale-capacity":
				input.Capacities[0].ObservedAt = input.Now.Add(-2 * MaxFactAge).Format(time.RFC3339Nano)
			case "future-capacity":
				input.Capacities[0].ObservedAt = input.Now.Add(time.Minute).Format(time.RFC3339Nano)
			case "fake-measured-target":
				input.Capacities[0].Status = "observed"
			case "negative-budget":
				input.Budgets[0].AdditionalBytes = -1
			case "overflow":
				input.Budgets[0].AdditionalBytes = MaxBytes
				input.Budgets[0].TemporaryBytes = 1
			case "unknown-domain":
				input.Required = append(input.Required, "unqualified-pool")
			case "duplicate-capacity":
				input.Capacities = append(input.Capacities, input.Capacities[0])
			}
			assessment, err := Assess(input)
			if err == nil && assessment.Executable {
				t.Fatalf("unsupported storage claim passed: %#v", assessment)
			}
		})
	}
}

func TestRequirementIdentityExcludesVolatileLocalFreeButBindsRemoteClaims(t *testing.T) {
	input := fixture()
	first, err := Assess(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Operator.AvailableBytes = pointer(2000)
	input.Operator.ObservedAt = input.Now.Add(time.Second).Format(time.RFC3339Nano)
	second, err := Assess(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.RequirementsDigest != second.RequirementsDigest {
		t.Fatal("ordinary local free-space movement invalidated requirement identity")
	}
	input.Capacities[0].Source = "different customer observation"
	changed, err := Assess(input)
	if err != nil {
		t.Fatal(err)
	}
	if changed.RequirementsDigest == first.RequirementsDigest {
		t.Fatal("changed remote provenance retained old requirement identity")
	}
}
