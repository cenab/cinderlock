package spec

import (
	"strings"
	"time"
)

const (
	WorkerMaxCPUMillis      int64 = 64000
	WorkerMaxBytes          int64 = 1 << 40
	WorkerMaxTimeoutSeconds int64 = 86400
)

type WorkerResources struct {
	CPUMillis             int64 `json:"cpuMillis" yaml:"cpuMillis"`
	MemoryBytes           int64 `json:"memoryBytes" yaml:"memoryBytes"`
	EphemeralStorageBytes int64 `json:"ephemeralStorageBytes" yaml:"ephemeralStorageBytes"`
	TemporaryBytes        int64 `json:"temporaryBytes" yaml:"temporaryBytes"`
	GPUCount              int64 `json:"gpuCount" yaml:"gpuCount"`
}

func ValidateWorkerResources(r *WorkerResources) error {
	if r == nil {
		return Err(2, "authored worker requires resources")
	}
	if r.CPUMillis < 1 || r.CPUMillis > WorkerMaxCPUMillis {
		return Err(2, "worker resources cpuMillis must be 1..%d", WorkerMaxCPUMillis)
	}
	if r.MemoryBytes < 1 || r.MemoryBytes > WorkerMaxBytes || r.EphemeralStorageBytes < 1 || r.EphemeralStorageBytes > WorkerMaxBytes {
		return Err(2, "worker resources memoryBytes and ephemeralStorageBytes must be 1..%d", WorkerMaxBytes)
	}
	if r.TemporaryBytes < 1 || r.TemporaryBytes > r.EphemeralStorageBytes {
		return Err(2, "worker resources temporaryBytes must be positive and at most ephemeralStorageBytes")
	}
	if r.GPUCount != 0 {
		return Err(2, "worker resources gpuCount must be zero; authored GPU allocation is unsupported")
	}
	return nil
}

// ScriptContract holds declarations, not executable expressions or permission
// grants. Application authors remain responsible for their actual effects.
type ScriptContract struct {
	Inputs        []string         `json:"inputs" yaml:"inputs"`
	Permissions   []string         `json:"permissions" yaml:"permissions"`
	SideEffects   []string         `json:"sideEffects" yaml:"sideEffects"`
	SuccessChecks []string         `json:"successChecks" yaml:"successChecks"`
	Retry         string           `json:"retry" yaml:"retry"`
	Resources     *WorkerResources `json:"resources" yaml:"resources"`
}

func isScriptOperation(o Operation) bool {
	switch o.Type {
	case "job", "migrate", "backup", "reindex":
		return true
	case "seed":
		return len(o.Command) != 0
	}
	return false
}

func validateScriptContract(o Operation) error {
	if !isScriptOperation(o) {
		if o.Script != nil {
			return Err(2, "operation %s cannot declare script on a non-script adapter", o.ID)
		}
		return nil
	}
	if err := validateScriptDeclaration(o.ID, o.Script); err != nil {
		return err
	}
	if o.TimeoutSeconds < 1 || o.TimeoutSeconds > WorkerMaxTimeoutSeconds {
		return Err(2, "script operation %s timeoutSeconds must be 1..%d", o.ID, WorkerMaxTimeoutSeconds)
	}
	if o.Image == "" || !validContractArgv(o.Command, true) || !validContractArgv(o.Args, false) || len(o.ReconcileCommand) != 0 && !validContractArgv(o.ReconcileCommand, true) {
		return Err(2, "script operation %s requires an image and bounded explicit argv without NUL bytes", o.ID)
	}
	switch o.Script.Retry {
	case "retry-safe":
		if !o.Idempotent {
			return Err(2, "retry-safe script operation %s must be idempotent", o.ID)
		}
	case "reconcilable":
		if o.Idempotent || len(o.ReconcileCommand) == 0 {
			return Err(2, "reconcilable script operation %s must be non-idempotent with explicit reconciliation argv", o.ID)
		}
	case "manual":
		if o.Idempotent || len(o.ReconcileCommand) != 0 {
			return Err(2, "manual script operation %s must be non-idempotent without reconciliation argv", o.ID)
		}
	}
	return nil
}

func validateCheckScript(c Check) error {
	if c.Type != "job" {
		if c.Script != nil {
			return Err(2, "check %s cannot declare script on a fixed adapter", c.ID)
		}
		return nil
	}
	if err := validateScriptDeclaration(c.ID, c.Script); err != nil {
		return err
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > WorkerMaxTimeoutSeconds {
		return Err(2, "Job check %s timeoutSeconds must be 1..%d", c.ID, WorkerMaxTimeoutSeconds)
	}
	if c.Script.Retry == "reconcilable" {
		return Err(2, "check %s cannot use unsupported authored reconciliation; use retry-safe or manual", c.ID)
	}
	return nil
}

func validateScriptDeclaration(id string, contract *ScriptContract) error {
	if contract == nil {
		return Err(2, "script %s requires a script contract", id)
	}
	if err := ValidateWorkerResources(contract.Resources); err != nil {
		return Err(2, "script %s: %v", id, err)
	}
	for _, field := range []struct {
		name   string
		values []string
	}{
		{"inputs", contract.Inputs},
		{"permissions", contract.Permissions},
		{"sideEffects", contract.SideEffects},
	} {
		if len(field.values) == 0 || len(field.values) > 64 {
			return Err(2, "script %s needs 1..64 %s descriptions", id, field.name)
		}
		for _, description := range field.values {
			if strings.TrimSpace(description) == "" || len(description) > 4096 {
				return Err(2, "script %s %s descriptions must be nonblank and at most 4096 bytes", id, field.name)
			}
		}
	}
	if len(contract.SuccessChecks) == 0 || len(contract.SuccessChecks) > 64 {
		return Err(2, "script %s needs 1..64 successChecks", id)
	}
	seen := map[string]bool{}
	for _, check := range contract.SuccessChecks {
		if !identifier.MatchString(check) || seen[check] {
			return Err(2, "script %s needs unique successChecks identifiers", id)
		}
		seen[check] = true
	}
	switch contract.Retry {
	case "retry-safe", "reconcilable", "manual":
	default:
		return Err(2, "script %s has unknown retry semantics %q", id, contract.Retry)
	}
	return nil
}

func validContractArgv(argv []string, command bool) bool {
	if len(argv) > 256 || command && (len(argv) == 0 || strings.TrimSpace(argv[0]) == "") {
		return false
	}
	for _, arg := range argv {
		if len(arg) > 4096 || strings.ContainsRune(arg, '\x00') {
			return false
		}
	}
	return true
}

func validateReleaseContracts(r Release) error {
	if err := validateScriptReferences(r.Spec.Operations, r.Spec.Checks, r.Spec.RequiredChecks, r.Spec.Assets); err != nil {
		return err
	}
	for _, rec := range r.Spec.Recovery {
		if err := validateScriptReferences(rec.Operations, rec.Checks, nil, r.Spec.Assets); err != nil {
			return Err(2, "recovery %s: %v", rec.ID, err)
		}
	}
	if err := validateIntermediateRoutes(r); err != nil {
		return err
	}
	return validateLicenseRequirement(r)
}

func validateScriptReferences(operations []Operation, checks []Check, required []string, assets []Asset) error {
	validate := func(owner, image string, contract *ScriptContract, self string) error {
		if contract == nil {
			return nil
		}
		if !nonoptionalImage(assets, image) {
			return Err(2, "script %s requires a declared nonoptional image asset", owner)
		}
		for _, id := range contract.SuccessChecks {
			if id == self {
				continue
			}
			c, ok := requiredRecipeCheck(checks, required, id)
			if !ok || c.Domain != "workflow" && c.Domain != "recovery" {
				return Err(2, "script %s success check %s must be a required application check in its own recipe", owner, id)
			}
			if !nonoptionalImage(assets, c.Image) {
				return Err(2, "script %s success check %s requires a declared nonoptional image asset", owner, id)
			}
		}
		return nil
	}
	for _, o := range operations {
		if err := validate("operation "+o.ID, o.Image, o.Script, ""); err != nil {
			return err
		}
	}
	for _, c := range checks {
		if err := validate("check "+c.ID, c.Image, c.Script, c.ID); err != nil {
			return err
		}
	}
	return nil
}

func requiredRecipeCheck(checks []Check, required []string, id string) (Check, bool) {
	for _, c := range checks {
		if c.ID == id {
			return c, c.Required || containsString(required, id)
		}
	}
	return Check{}, false
}

func nonoptionalImage(assets []Asset, ref string) bool {
	if ref == "" {
		return false
	}
	for _, a := range assets {
		if a.Type == "image" && (ref == a.ID || ref == a.Source || ref == a.Digest) {
			return !a.Optional
		}
	}
	return false
}

func validateIntermediateRoutes(r Release) error {
	from := map[string]Transition{}
	for _, t := range r.Spec.Transitions {
		if strings.TrimSpace(t.FromRelease) == "" {
			return Err(2, "transition %s needs a nonblank fromRelease", t.ID)
		}
		if _, exists := from[t.FromRelease]; exists {
			return Err(2, "duplicate fromRelease %q makes transitions ambiguous", t.FromRelease)
		}
		from[t.FromRelease] = t
	}
	for _, t := range r.Spec.Transitions {
		if len(t.IntermediateReleases) > 64 {
			return Err(2, "transition %s has more than 64 intermediate releases", t.ID)
		}
		seen := map[string]bool{}
		for _, version := range t.IntermediateReleases {
			if strings.TrimSpace(version) == "" || len(version) > 128 || seen[version] || version == "install" || version == t.FromRelease || version == r.Metadata.Version {
				return Err(2, "transition %s needs unique nonblank intermediate releases of at most 128 bytes, excluding install, fromRelease and target", t.ID)
			}
			seen[version] = true
		}
		if len(t.IntermediateReleases) != 0 {
			final := t.IntermediateReleases[len(t.IntermediateReleases)-1]
			if direct, exists := from[final]; !exists || len(direct.IntermediateReleases) != 0 {
				return Err(2, "transition %s needs a matching direct transition from final intermediate release %s", t.ID, final)
			}
		}
	}
	return nil
}

func validateLicenseRequirement(r Release) error {
	l := r.Spec.License
	if l == nil {
		return nil
	}
	if l.Mode != "offline" {
		return Err(2, "license mode must be offline")
	}
	if !identifier.MatchString(l.SecretRef) {
		return Err(2, "license secretRef must be a valid identifier")
	}
	if !identifier.MatchString(l.Check) {
		return Err(2, "license check must be a valid check identifier")
	}
	if l.MaxAgeSeconds < 1 || l.MaxAgeSeconds > 86400 {
		return Err(2, "license maxAgeSeconds must be 1..86400 for the durable completed entitlement validation observation")
	}
	if l.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, l.ExpiresAt); err != nil {
			return Err(2, "license expiresAt must be RFC3339")
		}
	}
	renewal := false
	for _, a := range r.Spec.Assets {
		if a.ID == l.RenewalAsset && !a.Optional && a.Type != "image" {
			renewal = true
			break
		}
	}
	if !renewal {
		return Err(2, "license renewalAsset must identify a declared nonoptional nonimage asset")
	}
	if err := validateLicenseCheck(*l, r.Spec.Checks, r.Spec.RequiredChecks, r.Spec.Assets); err != nil {
		return err
	}
	for _, rec := range r.Spec.Recovery {
		if len(rec.Operations) == 0 {
			continue
		}
		if err := validateLicenseCheck(*l, rec.Checks, nil, r.Spec.Assets); err != nil {
			return Err(2, "recovery %s: %v", rec.ID, err)
		}
	}
	return nil
}

func validateLicenseCheck(l LicenseRequirement, checks []Check, required []string, assets []Asset) error {
	c, ok := requiredRecipeCheck(checks, required, l.Check)
	if !ok || c.Type != "job" || c.Domain != "workflow" || c.ExpectedExitCode != 0 || len(c.Fixtures) != 0 || !containsString(c.SecretRefs, l.SecretRef) {
		return Err(2, "license check %s must be a required workflow Job without fixtures, with zero expected exit and consumption of secretRef %s", l.Check, l.SecretRef)
	}
	if !nonoptionalImage(assets, c.Image) {
		return Err(2, "license check %s requires a declared nonoptional image asset", l.Check)
	}
	return nil
}
