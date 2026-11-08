// Package storageplan calculates a conditional peak-space budget. It keeps
// storage domains separate and never turns a declaration into a measurement.
package storageplan

import (
	"slices"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

const Profile = "peaks-v1"
const MaxFactAge = time.Hour
const MaxBytes = int64(9007199254740991)

var Domains = []string{"operator", "registry", "runtime", "models", "indexes", "migrations", "backups"}

type Input struct {
	Profile                 string
	Inventory               spec.StorageInventory
	Required                []string
	Budgets                 []spec.StorageBudget
	Capacities              []spec.StorageCapacity
	Operator                spec.StorageCapacity
	OperatorAdditionalBytes int64
	AllowAssertions         bool
	BundleDigest            string
	SiteDigest              string
	PolicyDigest            string
	Now                     time.Time
}

func Add(first, second int64) (int64, error) {
	if first < 0 || second < 0 || first > MaxBytes || second > MaxBytes || first > MaxBytes-second {
		return 0, spec.Err(10, "storage byte count overflows supported integer range")
	}
	return first + second, nil
}

func Assess(input Input) (spec.StorageAssessment, error) {
	assessment := spec.StorageAssessment{Profile: input.Profile, Inputs: input.Inventory, Domains: []spec.StorageDomainPlan{}, Bindings: []spec.StorageBindingPlan{}, Findings: []spec.Finding{}, Executable: true}
	block := func(code, message string) {
		assessment.Executable = false
		assessment.Findings = append(assessment.Findings, spec.Finding{Code: code, Severity: "blocker", Message: message, Source: "storage profile " + Profile})
	}
	if input.Profile != Profile {
		block("STORAGE_PROFILE_UNSUPPORTED", "select the supported peaks-v1 storage profile")
		return assessment, nil
	}
	if len(input.Budgets) > len(Domains) || len(input.Capacities) > len(Domains)-1 {
		block("STORAGE_INPUT_LIMIT", "storage profile accepts one budget/capacity per supported domain")
		return assessment, nil
	}
	for _, count := range []int64{input.Inventory.BundleBytes, input.Inventory.VerifiedPayloadBytes, input.Inventory.ImageCompressedBytes, input.Inventory.ModelBytes, input.Inventory.LargestModelFileBytes, input.OperatorAdditionalBytes} {
		if count < 0 || count > MaxBytes {
			block("STORAGE_OVERFLOW", "inventory byte count exceeds the supported storage profile")
			return assessment, nil
		}
	}
	if input.Inventory.LargestModelFileBytes > input.Inventory.ModelBytes {
		block("STORAGE_INVENTORY_INVALID", "largest model file exceeds selected model bytes")
		return assessment, nil
	}
	required := map[string]bool{"operator": true}
	for _, domain := range input.Required {
		if !slices.Contains(Domains, domain) {
			block("STORAGE_DOMAIN_UNSUPPORTED", "unknown required storage domain: "+domain)
		} else {
			required[domain] = true
		}
	}
	budgets := map[string]spec.StorageBudget{}
	for _, budget := range input.Budgets {
		if !slices.Contains(Domains, budget.Domain) {
			block("STORAGE_DOMAIN_UNSUPPORTED", "unknown signed budget domain: "+budget.Domain)
			continue
		}
		if _, exists := budgets[budget.Domain]; exists {
			block("STORAGE_BUDGET_DUPLICATE", "duplicate signed storage budget: "+budget.Domain)
		}
		if _, err := Add(budget.AdditionalBytes, budget.TemporaryBytes); err != nil {
			block("STORAGE_OVERFLOW", "invalid signed storage budget: "+budget.Domain)
		}
		budgets[budget.Domain] = budget
		if budget.AdditionalBytes > 0 || budget.TemporaryBytes > 0 {
			required[budget.Domain] = true
		}
	}
	capacities := map[string]spec.StorageCapacity{}
	for _, capacity := range input.Capacities {
		if !slices.Contains(Domains, capacity.Domain) || capacity.Domain == "operator" {
			block("STORAGE_DOMAIN_UNSUPPORTED", "target capacity cannot replace the observed operator domain: "+capacity.Domain)
			continue
		}
		if _, exists := capacities[capacity.Domain]; exists {
			block("STORAGE_CAPACITY_DUPLICATE", "duplicate target storage capacity: "+capacity.Domain)
		}
		capacities[capacity.Domain] = capacity
	}
	capacities["operator"] = input.Operator
	if !input.AllowAssertions {
		block("STORAGE_ASSERTIONS_DENIED", "signed budgets and target assertions require storage-assertions in both Site and TrustPolicy")
	}
	bindings := map[string]*spec.StorageBindingPlan{}
	for _, domain := range Domains {
		row := spec.StorageDomainPlan{Domain: domain, Required: required[domain], Source: "not required by selected operations", Confidence: "not_required"}
		if !row.Required {
			assessment.Domains = append(assessment.Domains, row)
			continue
		}
		budget, hasBudget := budgets[domain]
		if !hasBudget {
			block("STORAGE_BUDGET_UNKNOWN", "signed additional/temporary budget is required for "+domain)
		}
		row.AdditionalBytes = budget.AdditionalBytes
		row.TemporaryBytes = budget.TemporaryBytes
		var additional int64
		switch domain {
		case "operator":
			additional = input.OperatorAdditionalBytes
		case "registry":
			additional = input.Inventory.ImageCompressedBytes
		case "models":
			additional = input.Inventory.ModelBytes
			row.TemporaryBytes = checkedAdd(row.TemporaryBytes, input.Inventory.LargestModelFileBytes, domain, block)
		}
		row.AdditionalBytes = checkedAdd(row.AdditionalBytes, additional, domain, block)
		capacity, exists := capacities[domain]
		row.Binding = capacity.Binding
		row.Source = "signed release budget; capacity: " + capacity.Source
		row.Confidence = "asserted"
		if domain == "registry" || domain == "models" {
			row.Source = "verified artifact logical bytes; " + row.Source
			row.Confidence = "verified_and_asserted"
		}
		if domain == "operator" {
			row.Confidence = "observed_and_declared"
			row.Source = "observed local statfs; verified existing bundle/cache logical bytes; signed future workspace budget"
		}
		if !hasBudget {
			row.Confidence = "unknown_budget"
			row.Source += "; signed expansion budget missing"
		}
		if !exists || capacity.AvailableBytes == nil || capacity.RetainedBytes == nil || capacity.Binding == "" || len(capacity.Binding) > 1024 || strings.TrimSpace(capacity.Source) == "" || len(capacity.Source) > 4096 {
			row.Confidence = "unknown"
			block("STORAGE_CAPACITY_UNKNOWN", "available, retained, binding and source facts are required for "+domain)
		}
		if domain == "operator" {
			if capacity.Status != "observed" {
				row.Confidence = "unknown"
				block("STORAGE_LOCAL_UNOBSERVED", "operator free space must come from actual local Statfs")
			}
		} else {
			if capacity.Status != "asserted" {
				row.Confidence = "unknown"
				block("STORAGE_CAPACITY_UNKNOWN", "remote capacity remains unknown without a qualified observation or explicitly admitted assertion: "+domain)
			}
			observed, err := time.Parse(time.RFC3339Nano, capacity.ObservedAt)
			if err != nil || input.Now.Before(observed) || input.Now.Sub(observed) > MaxFactAge {
				row.Confidence = "stale_or_unknown"
				block("STORAGE_CAPACITY_STALE", "target storage assertion needs a fresh local-time observation: "+domain)
			}
		}
		if capacity.AvailableBytes != nil {
			value := *capacity.AvailableBytes
			row.AvailableBytes = &value
			if value < 0 || value > MaxBytes {
				block("STORAGE_OVERFLOW", "invalid available bytes for "+domain)
			}
		}
		if capacity.RetainedBytes != nil {
			row.RetainedBytes = *capacity.RetainedBytes
			if row.RetainedBytes < 0 || row.RetainedBytes > MaxBytes {
				block("STORAGE_OVERFLOW", "invalid retained bytes for "+domain)
			}
		}
		needed := checkedAdd(row.AdditionalBytes, row.TemporaryBytes, domain, block)
		row.PeakBytes = checkedAdd(row.RetainedBytes, needed, domain, block)
		if row.AvailableBytes != nil && needed > *row.AvailableBytes {
			block("STORAGE_INSUFFICIENT", "additional and temporary bytes exceed available capacity in "+domain)
		}
		if row.Binding != "" {
			group, exists := bindings[row.Binding]
			if !exists {
				group = &spec.StorageBindingPlan{Binding: row.Binding, AvailableBytes: row.AvailableBytes, Source: capacity.Source, Confidence: capacity.Status}
				bindings[row.Binding] = group
			} else if group.AvailableBytes == nil || row.AvailableBytes == nil || *group.AvailableBytes != *row.AvailableBytes || group.Confidence != capacity.Status {
				block("STORAGE_BINDING_CONFLICT", "domains sharing a binding need consistent available-capacity facts: "+row.Binding)
			}
			group.RequiredAdditionalBytes = checkedAdd(group.RequiredAdditionalBytes, needed, row.Binding, block)
		}
		assessment.Domains = append(assessment.Domains, row)
	}
	keys := []string{}
	for key := range bindings {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		group := bindings[key]
		assessment.Bindings = append(assessment.Bindings, *group)
		if group.AvailableBytes == nil || group.RequiredAdditionalBytes > *group.AvailableBytes {
			block("STORAGE_BINDING_INSUFFICIENT", "combined domain additions exceed shared binding capacity: "+key)
		}
	}
	if assessment.Executable {
		assessment.Findings = append(assessment.Findings, spec.Finding{Code: "STORAGE_ASSERTED_SCOPE", Severity: "info", Message: "operator free space was observed; target free/retained capacity and runtime/migration/backup expansion remain explicitly admitted declarations", Source: "storage profile " + Profile})
	}
	identity := input.Operator
	identity.AvailableBytes = nil
	identity.ObservedAt = ""
	orderedRequired := []string{}
	for _, domain := range Domains {
		if required[domain] {
			orderedRequired = append(orderedRequired, domain)
		}
	}
	budgetList := slices.Clone(input.Budgets)
	slices.SortFunc(budgetList, func(a, b spec.StorageBudget) int { return strings.Compare(a.Domain, b.Domain) })
	capacityList := slices.Clone(input.Capacities)
	slices.SortFunc(capacityList, func(a, b spec.StorageCapacity) int { return strings.Compare(a.Domain, b.Domain) })
	digest, err := spec.Digest(struct {
		Profile                                string
		Inventory                              spec.StorageInventory
		Required                               []string
		Budgets                                []spec.StorageBudget
		Capacities                             []spec.StorageCapacity
		Operator                               spec.StorageCapacity
		OperatorAdditional                     int64
		Assertions                             bool
		BundleDigest, SiteDigest, PolicyDigest string
	}{input.Profile, input.Inventory, orderedRequired, budgetList, capacityList, identity, input.OperatorAdditionalBytes, input.AllowAssertions, input.BundleDigest, input.SiteDigest, input.PolicyDigest})
	if err != nil {
		block("STORAGE_INPUT_INVALID", "storage claims exceed canonical wire bounds")
		return assessment, nil
	}
	assessment.RequirementsDigest = digest
	return assessment, nil
}

func checkedAdd(first, second int64, domain string, block func(string, string)) int64 {
	result, err := Add(first, second)
	if err != nil {
		block("STORAGE_OVERFLOW", "storage arithmetic exceeds the supported range in "+domain)
		return 0
	}
	return result
}
