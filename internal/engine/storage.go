package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/storageplan"
	"golang.org/x/sys/unix"
)

// StoragePlan observes only the operator filesystem. Remote capacity remains
// an explicitly admitted Site assertion, not an invented target measurement.
func (e *Engine) StoragePlan(ctx context.Context, p spec.Plan, v *bundle.Verified, policy spec.TrustPolicy) (spec.StorageAssessment, error) {
	if err := ctx.Err(); err != nil {
		return spec.StorageAssessment{}, err
	}
	if e.Site.Spec.StorageProfile != storageplan.Profile {
		return storageplan.Assess(storageplan.Input{Profile: e.Site.Spec.StorageProfile})
	}
	inventory, required, operatorExtra, err := storageInventory(p, v)
	if err != nil {
		return storageFailure(e.Site.Spec.StorageProfile, err.Error()), nil
	}
	archive, err := os.Stat(p.BundlePath)
	if err != nil || !archive.Mode().IsRegular() {
		return storageFailure(e.Site.Spec.StorageProfile, "verified bundle file is unavailable for storage accounting"), nil
	}
	inventory.BundleBytes = archive.Size()
	operatorPath := e.Site.Spec.StorageOperatorPath
	if operatorPath == "" {
		operatorPath = e.StateDir
	}
	operatorPath, err = filepath.Abs(operatorPath)
	if err != nil {
		return spec.StorageAssessment{}, err
	}
	operator, err := observeOperatorStorage(operatorPath, inventory)
	if err != nil {
		return storageFailure(e.Site.Spec.StorageProfile, "operator free space could not be observed with local Statfs"), nil
	}
	for _, usedPath := range []string{e.StateDir, p.BundlePath, v.Root} {
		if usedPath == "" {
			return storageFailure(e.Site.Spec.StorageProfile, "actual operator workspace/cache binding is unavailable"), nil
		}
		observed, err := observeOperatorStorage(usedPath, inventory)
		if err != nil || observed.Binding != operator.Binding {
			return storageFailure(e.Site.Spec.StorageProfile, "peaks-v1 requires the operator probe, actual state/workspace, verified cache and bundle file on the same observed filesystem"), nil
		}
		if *observed.AvailableBytes < *operator.AvailableBytes {
			operator.AvailableBytes = observed.AvailableBytes
		}
	}
	input := storageplan.Input{Profile: e.Site.Spec.StorageProfile, Inventory: inventory, Required: required, Budgets: v.Index.Lock.Release.Spec.StorageBudgets, Capacities: e.Site.Spec.StorageCapacities, Operator: operator, OperatorAdditionalBytes: operatorExtra, AllowAssertions: slices.Contains(e.Site.Spec.AllowedActions, "storage-assertions") && slices.Contains(policy.Spec.AllowedActions, "storage-assertions"), BundleDigest: p.BundleDigest, SiteDigest: p.SiteDigest, PolicyDigest: p.PolicyDigest, Now: time.Now().UTC()}
	return storageplan.Assess(input)
}

func storageFailure(profile, message string) spec.StorageAssessment {
	return spec.StorageAssessment{Profile: profile, Domains: []spec.StorageDomainPlan{}, Bindings: []spec.StorageBindingPlan{}, Findings: []spec.Finding{{Code: "STORAGE_OBSERVATION_UNAVAILABLE", Severity: "blocker", Message: message, Source: "storage profile"}}, Executable: false}
}

func observeOperatorStorage(path string, inventory spec.StorageInventory) (spec.StorageCapacity, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return spec.StorageCapacity{}, err
	}
	if stat.Bsize <= 0 || uint64(stat.Bsize) > uint64(storageplan.MaxBytes) || stat.Bavail > uint64(storageplan.MaxBytes)/uint64(stat.Bsize) {
		return spec.StorageCapacity{}, spec.Err(10, "observed filesystem free bytes exceed the supported range")
	}
	available := int64(stat.Bavail) * int64(stat.Bsize)
	retained, err := storageplan.Add(inventory.BundleBytes, inventory.VerifiedPayloadBytes)
	if err != nil {
		return spec.StorageCapacity{}, err
	}
	return spec.StorageCapacity{Domain: "operator", Binding: fmt.Sprintf("operator-fs:%v", stat.Fsid), Source: "local Statfs at " + path, AvailableBytes: &available, RetainedBytes: &retained, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: "observed"}, nil
}

func storageInventory(p spec.Plan, v *bundle.Verified) (spec.StorageInventory, []string, int64, error) {
	inventory := spec.StorageInventory{}
	var operatorExtra int64
	required := map[string]bool{"operator": true}
	payloads := map[string]int64{}
	for _, payload := range v.Index.Payloads {
		if previous, exists := payloads[payload.Path]; exists {
			if previous != payload.Size {
				return inventory, nil, 0, spec.Err(10, "conflicting verified payload sizes")
			}
			continue
		}
		payloads[payload.Path] = payload.Size
		var err error
		inventory.VerifiedPayloadBytes, err = storageplan.Add(inventory.VerifiedPayloadBytes, payload.Size)
		if err != nil {
			return inventory, nil, 0, err
		}
	}
	if len(v.Index.Payloads) == 0 {
		return inventory, nil, 0, spec.Err(10, "verified payload closure is unavailable for storage accounting")
	}
	imports := map[string]bool{}
	allImages := false
	matchedImports := map[string]bool{}
	helmed := false
	for _, operation := range p.Operations {
		switch operation.Type {
		case "import":
			required["registry"] = true
			if operation.Asset == "" {
				allImages = true
			} else {
				imports[operation.Asset] = true
			}
		case "helm":
			required["runtime"] = true
			helmed = true
		case "job", "migrate", "backup", "reindex", "seed", "probe":
			required["runtime"] = true
		}
		switch operation.Type {
		case "migrate":
			required["migrations"] = true
		case "backup":
			required["backups"] = true
		case "reindex":
			required["indexes"] = true
		case "seed":
			required["models"] = true
			asset, err := v.Asset(operation.Asset)
			if err != nil || len(asset.Files) == 0 {
				return inventory, nil, 0, spec.Err(10, "selected model file closure is unavailable")
			}
			for _, file := range asset.Files {
				inventory.ModelBytes, err = storageplan.Add(inventory.ModelBytes, file.Size)
				if err != nil {
					return inventory, nil, 0, err
				}
				if file.Size > inventory.LargestModelFileBytes {
					inventory.LargestModelFileBytes = file.Size
				}
			}
		}
	}
	if len(p.Checks) > 0 {
		required["runtime"] = true
	}
	if helmed && v.Index.Lock.Release.Spec.AIProfile.IndexRevision != "" {
		required["indexes"] = true
	}
	for _, asset := range v.Index.Lock.Assets {
		if asset.Type == "image" && (allImages || imports[asset.ID]) {
			matchedImports[asset.ID] = true
			if len(asset.Files) == 0 {
				return inventory, nil, 0, spec.Err(10, "selected OCI closure sizes are unavailable")
			}
			// Each target repository receives its own closure. Cross-repository
			// physical deduplication is not assumed from equal layer digests.
			seen := map[string]int64{}
			for _, file := range asset.Files {
				if previous, exists := seen[file.Digest]; exists {
					if previous != file.Size {
						return inventory, nil, 0, spec.Err(10, "conflicting OCI descriptor sizes")
					}
					continue
				}
				seen[file.Digest] = file.Size
				var err error
				inventory.ImageCompressedBytes, err = storageplan.Add(inventory.ImageCompressedBytes, file.Size)
				if err != nil {
					return inventory, nil, 0, err
				}
			}
		}
		if helmed && (asset.ID == "cinderlock-chart" || strings.HasPrefix(asset.ID, "cinderlock-values-")) {
			for _, file := range asset.Files {
				var err error
				operatorExtra, err = storageplan.Add(operatorExtra, file.Size)
				if err != nil {
					return inventory, nil, 0, err
				}
			}
		}
	}
	for id := range imports {
		if !matchedImports[id] {
			return inventory, nil, 0, spec.Err(10, "selected image import closure is unavailable")
		}
	}
	if allImages && len(matchedImports) == 0 {
		return inventory, nil, 0, spec.Err(10, "selected image import has no closure to account")
	}
	list := []string{}
	for domain := range required {
		list = append(list, domain)
	}
	slices.Sort(list)
	return inventory, list, operatorExtra, nil
}

func (e *Engine) addStorageFindings(ctx context.Context, p *spec.Plan, v *bundle.Verified, policy spec.TrustPolicy) {
	if e.Site.Spec.StorageProfile == "" {
		p.Findings = append(p.Findings, spec.Finding{Code: "STORAGE_LEGACY_UNQUALIFIED", Severity: "info", Message: "legacy single-capacity assertion does not qualify per-domain storage; select peaks-v1 for a measured operator and explicitly scoped target budget", Source: "Site capacityBytes"})
		return
	}
	assessment, err := e.StoragePlan(ctx, *p, v, policy)
	if err != nil {
		assessment = storageFailure(e.Site.Spec.StorageProfile, "storage inputs could not be evaluated")
	}
	p.Storage = &assessment
	p.Findings = append(p.Findings, assessment.Findings...)
	if !assessment.Executable {
		p.Executable = false
	}
}

func (e *Engine) checkStoragePlan(ctx context.Context, p spec.Plan, v *bundle.Verified, policy spec.TrustPolicy, initial bool) error {
	if e.Site.Spec.StorageProfile == "" {
		if p.Storage != nil {
			return spec.Err(11, "qualified storage metadata cannot be attached to a legacy storage Site")
		}
		return nil
	}
	if p.Storage == nil || p.Storage.Profile != e.Site.Spec.StorageProfile || p.Storage.RequirementsDigest == "" {
		return spec.Err(10, "plan is missing its explicit storage assessment; create a new plan")
	}
	if !initial {
		return nil
	}
	fresh, err := e.StoragePlan(ctx, p, v, policy)
	if err != nil {
		return err
	}
	if !fresh.Executable {
		return spec.Err(10, "current peak storage requirements are not satisfied; create a new plan and inspect its storage findings")
	}
	if fresh.RequirementsDigest != p.Storage.RequirementsDigest {
		return spec.Err(11, "storage requirements or filesystem bindings changed after planning")
	}
	previous := storageApprovalProjection(*p.Storage)
	current := storageApprovalProjection(fresh)
	a, err := spec.Digest(previous)
	if err != nil {
		return err
	}
	b, err := spec.Digest(current)
	if err != nil {
		return err
	}
	if a != b {
		return spec.Err(11, "submitted storage metadata differs from the computed peak plan")
	}
	return nil
}

func storageApprovalProjection(value spec.StorageAssessment) spec.StorageAssessment {
	value.Domains = slices.Clone(value.Domains)
	value.Bindings = slices.Clone(value.Bindings)
	operatorBinding := ""
	for i := range value.Domains {
		if value.Domains[i].Domain == "operator" {
			operatorBinding = value.Domains[i].Binding
			value.Domains[i].AvailableBytes = nil
		}
	}
	for i := range value.Bindings {
		if value.Bindings[i].Binding == operatorBinding {
			value.Bindings[i].AvailableBytes = nil
		}
	}
	return value
}
