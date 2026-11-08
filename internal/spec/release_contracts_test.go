package spec

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func scriptRelease() Release {
	r := Release{Header: NewHeader("Release"), Spec: ReleaseSpec{
		Profile: "cpu-test", Deployment: Deployment{Type: "helm", Chart: "chart.tgz"},
		Assets:         []Asset{{ID: "runner", Type: "image", Source: "registry.invalid/runner:1"}},
		Operations:     []Operation{{ID: "migrate", Type: "migrate", Image: "runner", Command: []string{"/app/migrate"}, Idempotent: true, TimeoutSeconds: 30}},
		Checks:         []Check{{ID: "workflow", Type: "job", Domain: "workflow", Image: "runner", Command: []string{"/app/verify"}, Required: true, TimeoutSeconds: 30}},
		RequiredChecks: []string{"workflow"},
		Transitions:    []Transition{{ID: "upgrade", FromRelease: "1.0.0", Operations: []string{"migrate"}, Recovery: "manual"}},
		Recovery:       []Recovery{{ID: "manual", ToRelease: "1.0.0"}},
	}}
	r.Metadata = Metadata{Application: "app", Version: "2.0.0", Channel: "stable", Sequence: 2}
	return r
}

func TestReleaseRejectsUnclassifiedScript(t *testing.T) {
	if err := ValidateRelease(scriptRelease()); err == nil {
		t.Fatal("mutating script without explicit inputs, permissions, effects, success checks, and retry classification was accepted")
	}
	for _, adapter := range []string{"job", "migrate", "backup", "reindex", "seed"} {
		for _, recovery := range []bool{false, true} {
			name := adapter + "/main"
			if recovery {
				name = adapter + "/recovery"
			}
			t.Run(name, func(t *testing.T) {
				r := classifiedScriptRelease()
				op := r.Spec.Operations[0]
				op.Type, op.Script = adapter, nil
				if recovery {
					r.Spec.Recovery[0].Operations = []Operation{op}
				} else {
					r.Spec.Operations[0] = op
				}
				if err := ValidateRelease(r); err == nil || !strings.Contains(err.Error(), "script contract") {
					t.Fatalf("missing script contract: got %v", err)
				}
			})
		}
	}
}

func classifiedScriptRelease() Release {
	r := scriptRelease()
	r.Spec.Checks[0].Script = checkContract("workflow")
	r.Spec.Operations[0].Script = &ScriptContract{
		Inputs: []string{"application database schema"}, Permissions: []string{"vendor-declared schema write access"},
		SideEffects: []string{"updates the schema revision"}, SuccessChecks: []string{"workflow"}, Retry: "retry-safe",
		Resources: &WorkerResources{CPUMillis: 100, MemoryBytes: 256 << 20, EphemeralStorageBytes: 64 << 20, TemporaryBytes: 16 << 20},
	}
	return r
}

func checkContract(id string) *ScriptContract {
	return &ScriptContract{Inputs: []string{"locked image and explicit check argv"}, Permissions: []string{"application test access; no Kubernetes API token"}, SideEffects: []string{"declared application check only"}, SuccessChecks: []string{id}, Retry: "manual", Resources: &WorkerResources{CPUMillis: 100, MemoryBytes: 256 << 20, EphemeralStorageBytes: 64 << 20, TemporaryBytes: 16 << 20}}
}

func TestJobCheckScriptContractsAndOptionalEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Release)
		want   string
	}{
		{"optional-self-evidence", func(r *Release) {}, ""},
		{"missing-contract", func(r *Release) { r.Spec.Checks[1].Script = nil }, "script contract"},
		{"unknown-retry", func(r *Release) { r.Spec.Checks[1].Script.Retry = "automatic" }, "unknown retry"},
		{"unsupported-reconciliation", func(r *Release) { r.Spec.Checks[1].Script.Retry = "reconcilable" }, "unsupported authored reconciliation"},
		{"missing-evidence", func(r *Release) { r.Spec.Checks[1].Script.SuccessChecks = []string{"absent"} }, "required application"},
		{"operation-cannot-use-optional", func(r *Release) { r.Spec.Operations[0].Script.SuccessChecks = []string{"optional"} }, "required application"},
		{"required-workflow-still-mandatory", func(r *Release) { r.Spec.RequiredChecks = nil; r.Spec.Checks[0].Required = false }, "mandatory"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := classifiedScriptRelease()
			check := Check{ID: "optional", Type: "job", Domain: "workflow", Image: "runner", Command: []string{"/app/optional-check"}, Script: checkContract("optional"), TimeoutSeconds: 30}
			r.Spec.Checks = append(r.Spec.Checks, check)
			test.change(&r)
			assertContractResult(t, ValidateRelease(r), test.want)
		})
	}
}

func assertContractResult(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if err == nil || ExitCode(err) != 2 || !strings.Contains(err.Error(), want) {
		t.Fatalf("want %q validation error, got %v", want, err)
	}
}

func TestReleaseScriptContract(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Operation)
		want   string
	}{
		{"retry-safe", func(o *Operation) {}, ""},
		{"retry-safe-with-reconciliation", func(o *Operation) { o.ReconcileCommand = []string{"/app/reconcile"} }, ""},
		{"reconcilable", func(o *Operation) {
			o.Script.Retry, o.Idempotent, o.ReconcileCommand = "reconcilable", false, []string{"/app/reconcile"}
		}, ""},
		{"manual", func(o *Operation) { o.Script.Retry, o.Idempotent = "manual", false }, ""},
		{"empty-argument", func(o *Operation) { o.Command = append(o.Command, ""); o.Args = []string{""} }, ""},
		{"declarations-are-prose", func(o *Operation) { o.Script.Permissions = []string{"no policy evaluation: permit(anything)"} }, ""},
		{"maximum-descriptions", func(o *Operation) { o.Script.Inputs = strings.Fields(strings.Repeat("declared ", 64)) }, ""},
		{"maximum-description", func(o *Operation) { o.Script.SideEffects = []string{strings.Repeat("x", 4096)} }, ""},
		{"maximum-arguments", func(o *Operation) { o.Args = strings.Fields(strings.Repeat("arg ", 256)) }, ""},
		{"maximum-argument", func(o *Operation) { o.Args = []string{strings.Repeat("x", 4096)} }, ""},
		{"maximum-timeout", func(o *Operation) { o.TimeoutSeconds = 86400 }, ""},
		{"missing-inputs", func(o *Operation) { o.Script.Inputs = nil }, "inputs"},
		{"missing-permissions", func(o *Operation) { o.Script.Permissions = nil }, "permissions"},
		{"missing-effects", func(o *Operation) { o.Script.SideEffects = nil }, "sideEffects"},
		{"blank-description", func(o *Operation) { o.Script.Inputs = []string{"\t \n"} }, "nonblank"},
		{"long-description", func(o *Operation) { o.Script.SideEffects = []string{strings.Repeat("x", 4097)} }, "4096"},
		{"many-descriptions", func(o *Operation) { o.Script.Permissions = strings.Fields(strings.Repeat("declared ", 65)) }, "1..64"},
		{"missing-success", func(o *Operation) { o.Script.SuccessChecks = nil }, "successChecks"},
		{"blank-success", func(o *Operation) { o.Script.SuccessChecks = []string{" "} }, "successChecks"},
		{"duplicate-success", func(o *Operation) { o.Script.SuccessChecks = []string{"workflow", "workflow"} }, "successChecks"},
		{"unknown-retry", func(o *Operation) { o.Script.Retry = "best-effort" }, "unknown retry"},
		{"empty-retry", func(o *Operation) { o.Script.Retry = "" }, "unknown retry"},
		{"unsafe-retry", func(o *Operation) { o.Idempotent = false }, "idempotent"},
		{"idempotent-reconcilable", func(o *Operation) {
			o.Script.Retry, o.ReconcileCommand = "reconcilable", []string{"/app/reconcile"}
		}, "non-idempotent"},
		{"missing-reconciliation", func(o *Operation) { o.Script.Retry, o.Idempotent = "reconcilable", false }, "reconciliation"},
		{"idempotent-manual", func(o *Operation) { o.Script.Retry = "manual" }, "non-idempotent"},
		{"manual-reconciliation", func(o *Operation) {
			o.Script.Retry, o.Idempotent, o.ReconcileCommand = "manual", false, []string{"/app/reconcile"}
		}, "without reconciliation"},
		{"missing-command", func(o *Operation) { o.Command = nil }, "argv"},
		{"blank-entrypoint", func(o *Operation) { o.Command = []string{" \t"} }, "argv"},
		{"nul-command", func(o *Operation) { o.Command = []string{"/app/migrate", "a\x00b"} }, "argv"},
		{"nul-argument", func(o *Operation) { o.Args = []string{"a\x00b"} }, "argv"},
		{"long-argument", func(o *Operation) { o.Args = []string{strings.Repeat("x", 4097)} }, "argv"},
		{"many-arguments", func(o *Operation) { o.Args = strings.Fields(strings.Repeat("arg ", 257)) }, "argv"},
		{"blank-reconciliation", func(o *Operation) {
			o.Script.Retry, o.Idempotent, o.ReconcileCommand = "reconcilable", false, []string{" "}
		}, "argv"},
		{"negative-timeout", func(o *Operation) { o.TimeoutSeconds = -1 }, "timeout"},
		{"missing-timeout", func(o *Operation) { o.TimeoutSeconds = 0 }, "timeout"},
		{"long-timeout", func(o *Operation) { o.TimeoutSeconds = 86401 }, "timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := classifiedScriptRelease()
			test.change(&r.Spec.Operations[0])
			assertContractResult(t, ValidateOperation(r.Spec.Operations[0]), test.want)
			assertContractResult(t, ValidateRelease(r), test.want)
		})
	}
}

func TestReleaseRejectsScriptOnAdapters(t *testing.T) {
	for _, adapter := range []string{"helm", "restart", "import", "gitops", "seed"} {
		t.Run(adapter, func(t *testing.T) {
			r := classifiedScriptRelease()
			r.Spec.Operations[0].Type = adapter
			if adapter == "seed" {
				r.Spec.Operations[0].Command = nil
			}
			if err := ValidateRelease(r); err == nil || !strings.Contains(err.Error(), "non-script adapter") {
				t.Fatalf("script on adapter: got %v", err)
			}
			r.Spec.Operations[0].Script = nil
			if err := ValidateRelease(r); err != nil {
				t.Fatal("adapter without script contract:", err)
			}
		})
	}
}

func TestReleaseScriptReferences(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Release)
		want   string
	}{
		{"asset-ids", func(r *Release) {}, ""},
		{"image-sources", func(r *Release) {
			r.Spec.Operations[0].Image, r.Spec.Checks[0].Image = r.Spec.Assets[0].Source, r.Spec.Assets[1].Source
		}, ""},
		{"image-digests", func(r *Release) {
			r.Spec.Assets[0].Digest, r.Spec.Assets[1].Digest = Hash([]byte("runner")), Hash([]byte("verifier"))
			r.Spec.Operations[0].Image, r.Spec.Checks[0].Image = r.Spec.Assets[0].Digest, r.Spec.Assets[1].Digest
		}, ""},
		{"required-by-list", func(r *Release) { r.Spec.Checks[0].Required = false }, ""},
		{"recovery-domain", func(r *Release) { r.Spec.Checks[0].Domain = "recovery" }, ""},
		{"missing-operation-image", func(r *Release) { r.Spec.Operations[0].Image = "undeclared" }, "image"},
		{"optional-operation-image", func(r *Release) { r.Spec.Assets[0].Optional = true }, "image"},
		{"nonimage-operation-image", func(r *Release) { r.Spec.Assets[0].Type = "file" }, "image"},
		{"missing-success-image", func(r *Release) { r.Spec.Checks[0].Image = "" }, "image"},
		{"undeclared-success-image", func(r *Release) { r.Spec.Checks[0].Image = "undeclared" }, "image"},
		{"optional-success-image", func(r *Release) { r.Spec.Assets[1].Optional = true }, "image"},
		{"optional-first-image-match", func(r *Release) {
			r.Spec.Assets[1].Optional = true
			r.Spec.Assets = append(r.Spec.Assets, Asset{ID: "other-verifier", Type: "image", Source: "verifier"})
		}, "image"},
		{"nonimage-success-image", func(r *Release) { r.Spec.Assets[1].Type = "file" }, "image"},
		{"missing-success-check", func(r *Release) { r.Spec.Operations[0].Script.SuccessChecks = []string{"missing"} }, "required application"},
		{"nonrequired-success-check", func(r *Release) {
			r.Spec.Checks[0].Required, r.Spec.RequiredChecks = false, []string{"acceptance"}
		}, "required application"},
		{"readiness-success", func(r *Release) { r.Spec.Checks[0].Domain = "readiness" }, "required application"},
		{"integrity-success", func(r *Release) { r.Spec.Checks[0].Domain = "integrity" }, "required application"},
		{"blank-success-command", func(r *Release) { r.Spec.Checks[0].Command = []string{" "} }, "argv"},
		{"invalid-success-timeout", func(r *Release) { r.Spec.Checks[0].TimeoutSeconds = -1 }, "timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := classifiedScriptRelease()
			r.Spec.Assets = append(r.Spec.Assets, Asset{ID: "verifier", Type: "image", Source: "registry.invalid/verifier:1"})
			r.Spec.Checks[0].Image = "verifier"
			acceptance := r.Spec.Checks[0]
			acceptance.ID = "acceptance"
			r.Spec.Checks = append(r.Spec.Checks, acceptance)
			r.Spec.RequiredChecks = append(r.Spec.RequiredChecks, acceptance.ID)
			test.change(&r)
			assertContractResult(t, ValidateRelease(r), test.want)
		})
	}
}

func TestReleaseScriptRecoveryScope(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Release)
		want   string
	}{
		{"own-recipe", func(r *Release) {}, ""},
		{"main-cannot-borrow-recovery", func(r *Release) {
			r.Spec.Operations[0].Script.SuccessChecks = []string{"recovered"}
		}, "required application"},
		{"recovery-cannot-borrow-main", func(r *Release) {
			r.Spec.Recovery[0].Operations[0].Script.SuccessChecks = []string{"workflow"}
		}, "required application"},
		{"main-required-list-does-not-apply", func(r *Release) {
			r.Spec.Recovery[0].Operations[0].Script.SuccessChecks = []string{"workflow"}
			r.Spec.Recovery[0].Checks[0].ID, r.Spec.Recovery[0].Checks[0].Required = "workflow", false
		}, "required application"},
		{"duplicate-recovery-check", func(r *Release) {
			r.Spec.Recovery[0].Checks = append(r.Spec.Recovery[0].Checks, r.Spec.Recovery[0].Checks[0])
		}, "duplicate check"},
		{"duplicate-recovery-operation", func(r *Release) {
			r.Spec.Recovery[0].Operations = append(r.Spec.Recovery[0].Operations, r.Spec.Recovery[0].Operations[0])
		}, "duplicate operation"},
		{"unknown-recovery-dependency", func(r *Release) {
			r.Spec.Recovery[0].Operations[0].DependsOn = []string{"main-only"}
		}, "invalid dependency"},
		{"recovery-dependency-cycle", func(r *Release) {
			other := r.Spec.Recovery[0].Operations[0]
			other.ID, other.DependsOn = "other", []string{"undo"}
			r.Spec.Recovery[0].Operations[0].DependsOn = []string{"other"}
			r.Spec.Recovery[0].Operations = append(r.Spec.Recovery[0].Operations, other)
		}, "dependency cycle"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := classifiedScriptRelease()
			op := classifiedScriptRelease().Spec.Operations[0]
			op.ID, op.Script.SuccessChecks = "undo", []string{"recovered"}
			check := r.Spec.Checks[0]
			check.ID, check.Domain = "recovered", "recovery"
			check.Script = checkContract("recovered")
			r.Spec.Recovery[0].Operations, r.Spec.Recovery[0].Checks = []Operation{op}, []Check{check}
			test.change(&r)
			assertContractResult(t, ValidateRelease(r), test.want)
		})
	}
}

func TestReleaseIntermediateRoutes(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Release)
		want   string
	}{
		{"declared-route", func(r *Release) {}, ""},
		{"maximum-release-length", func(r *Release) { r.Spec.Transitions[0].IntermediateReleases[0] = strings.Repeat("v", 128) }, ""},
		{"maximum-route", func(r *Release) {
			route := make([]string, 64)
			for i := range route {
				route[i] = fmt.Sprintf("1.%d.0", i+1)
			}
			r.Spec.Transitions[0].IntermediateReleases, r.Spec.Transitions[1].FromRelease = route, route[len(route)-1]
		}, ""},
		{"direct-transition", func(r *Release) { r.Spec.Transitions[0].IntermediateReleases = nil }, ""},
		{"blank", func(r *Release) { r.Spec.Transitions[0].IntermediateReleases[0] = " \t" }, "intermediate"},
		{"duplicate", func(r *Release) { r.Spec.Transitions[0].IntermediateReleases[0] = "1.5.0" }, "intermediate"},
		{"install", func(r *Release) { r.Spec.Transitions[0].IntermediateReleases[0] = "install" }, "intermediate"},
		{"current-release", func(r *Release) { r.Spec.Transitions[0].IntermediateReleases[0] = "1.0.0" }, "intermediate"},
		{"target-release", func(r *Release) { r.Spec.Transitions[0].IntermediateReleases[0] = r.Metadata.Version }, "intermediate"},
		{"long-release", func(r *Release) { r.Spec.Transitions[0].IntermediateReleases[0] = strings.Repeat("v", 129) }, "intermediate"},
		{"many-releases", func(r *Release) {
			route := make([]string, 65)
			for i := range route {
				route[i] = fmt.Sprintf("1.%d.0", i+1)
			}
			r.Spec.Transitions[0].IntermediateReleases, r.Spec.Transitions[1].FromRelease = route, route[len(route)-1]
		}, "intermediate"},
		{"missing-final-direct", func(r *Release) { r.Spec.Transitions[1].FromRelease = "1.6.0" }, "direct transition"},
		{"final-is-another-route", func(r *Release) {
			r.Spec.Transitions[1].IntermediateReleases = []string{"1.8.0"}
			direct := r.Spec.Transitions[1]
			direct.ID, direct.FromRelease, direct.IntermediateReleases = "final-direct", "1.8.0", nil
			r.Spec.Transitions = append(r.Spec.Transitions, direct)
		}, "direct transition"},
		{"duplicate-from-release", func(r *Release) {
			duplicate := r.Spec.Transitions[0]
			duplicate.ID = "ambiguous"
			r.Spec.Transitions = append(r.Spec.Transitions, duplicate)
		}, "duplicate fromRelease"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := classifiedScriptRelease()
			r.Spec.Transitions[0].IntermediateReleases = []string{"1.1.0", "1.5.0"}
			direct := r.Spec.Transitions[0]
			direct.ID, direct.FromRelease, direct.IntermediateReleases = "direct", "1.5.0", nil
			r.Spec.Transitions = append(r.Spec.Transitions, direct)
			test.change(&r)
			assertContractResult(t, ValidateRelease(r), test.want)
		})
	}
}

func licensedScriptRelease() Release {
	r := classifiedScriptRelease()
	r.Spec.Assets = append(r.Spec.Assets,
		Asset{ID: "license-runner", Type: "image", Source: "registry.invalid/license:2"},
		Asset{ID: "renewal", Type: "file", Source: "license-renewal.txt"},
		Asset{ID: "legacy-runner", Type: "image", Source: "registry.invalid/license:1"},
	)
	r.Spec.License = &LicenseRequirement{Mode: "offline", SecretRef: "entitlement", Check: "license", MaxAgeSeconds: 3600, RenewalAsset: "renewal"}
	check := Check{ID: "license", Type: "job", Domain: "workflow", Required: true, Image: "license-runner", Command: []string{"/app/validate-entitlement"}, SecretRefs: []string{"entitlement"}, Script: checkContract("license"), TimeoutSeconds: 30}
	r.Spec.Checks = append(r.Spec.Checks, check)
	check.Image, check.Command = "legacy-runner", []string{"/legacy/validate-entitlement"}
	check.Script = checkContract("license")
	r.Spec.Recovery[0].Operations = []Operation{{ID: "restore", Type: "helm"}}
	r.Spec.Recovery[0].Checks = []Check{check}
	return r
}

func TestReleaseLicenseContract(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Release)
		want   string
	}{
		{"offline-with-recovery-recipe", func(r *Release) {}, ""},
		{"minimum-age", func(r *Release) { r.Spec.License.MaxAgeSeconds = 1 }, ""},
		{"maximum-age", func(r *Release) { r.Spec.License.MaxAgeSeconds = 86400 }, ""},
		{"past-expiration-is-static", func(r *Release) { r.Spec.License.ExpiresAt = "2000-01-01T00:00:00Z" }, ""},
		{"required-by-list", func(r *Release) {
			r.Spec.Checks[1].Required = false
			r.Spec.RequiredChecks = append(r.Spec.RequiredChecks, "license")
		}, ""},
		{"online-mode", func(r *Release) { r.Spec.License.Mode = "online" }, "offline"},
		{"missing-mode", func(r *Release) { r.Spec.License.Mode = "" }, "offline"},
		{"zero-age", func(r *Release) { r.Spec.License.MaxAgeSeconds = 0 }, "maxAgeSeconds"},
		{"negative-age", func(r *Release) { r.Spec.License.MaxAgeSeconds = -1 }, "maxAgeSeconds"},
		{"excessive-age", func(r *Release) { r.Spec.License.MaxAgeSeconds = 86401 }, "maxAgeSeconds"},
		{"invalid-expiration", func(r *Release) { r.Spec.License.ExpiresAt = "tomorrow" }, "expiresAt"},
		{"missing-material-ref", func(r *Release) { r.Spec.License.SecretRef = "" }, "secretRef"},
		{"invalid-material-ref", func(r *Release) { r.Spec.License.SecretRef = "license token" }, "secretRef"},
		{"missing-renewal", func(r *Release) { r.Spec.License.RenewalAsset = "" }, "renewalAsset"},
		{"unknown-renewal", func(r *Release) { r.Spec.License.RenewalAsset = "missing" }, "renewalAsset"},
		{"optional-renewal", func(r *Release) { r.Spec.Assets[2].Optional = true }, "renewalAsset"},
		{"image-renewal", func(r *Release) { r.Spec.Assets[2].Type = "image" }, "renewalAsset"},
		{"missing-check-id", func(r *Release) { r.Spec.License.Check = "" }, "check"},
		{"unknown-check", func(r *Release) { r.Spec.License.Check = "missing" }, "license check"},
		{"nonrequired-check", func(r *Release) { r.Spec.Checks[1].Required = false }, "license check"},
		{"readiness-check", func(r *Release) { r.Spec.Checks[1].Domain = "readiness" }, "license check"},
		{"recovery-domain-check", func(r *Release) { r.Spec.Checks[1].Domain = "recovery" }, "license check"},
		{"http-check", func(r *Release) {
			r.Spec.Checks[1].Type, r.Spec.Checks[1].URL, r.Spec.Checks[1].ExpectedStatus = "http", "http://app/license", 200
			r.Spec.Checks[1].Script, r.Spec.Checks[1].Command = nil, nil
		}, "license check"},
		{"missing-command", func(r *Release) { r.Spec.Checks[1].Command = nil }, "argv"},
		{"blank-command", func(r *Release) { r.Spec.Checks[1].Command = []string{" "} }, "argv"},
		{"nul-command", func(r *Release) { r.Spec.Checks[1].Command = []string{"/app/license", "a\x00b"} }, "argv"},
		{"nonzero-exit", func(r *Release) { r.Spec.Checks[1].ExpectedExitCode = 1 }, "license check"},
		{"missing-image", func(r *Release) { r.Spec.Checks[1].Image = "" }, "image"},
		{"undeclared-image", func(r *Release) { r.Spec.Checks[1].Image = "missing" }, "image"},
		{"optional-image", func(r *Release) { r.Spec.Assets[1].Optional = true }, "image"},
		{"nonimage-image", func(r *Release) { r.Spec.Assets[1].Type = "file" }, "image"},
		{"unconsumed-material", func(r *Release) { r.Spec.Checks[1].SecretRefs = nil }, "license check"},
		{"different-material", func(r *Release) { r.Spec.Checks[1].SecretRefs = []string{"other-license"} }, "license check"},
		{"empty-recovery", func(r *Release) { r.Spec.Recovery[0].Operations, r.Spec.Recovery[0].Checks = nil, nil }, ""},
		{"manual-script-recovery", func(r *Release) {
			op := classifiedScriptRelease().Spec.Operations[0]
			op.Script.Retry, op.Idempotent = "manual", false
			r.Spec.Recovery[0].Operations, r.Spec.Recovery[0].Checks = []Operation{op}, []Check{r.Spec.Checks[0]}
		}, "license check"},
		{"recovery-missing-check", func(r *Release) { r.Spec.Recovery[0].Checks = nil }, "license check"},
		{"recovery-different-check-id", func(r *Release) {
			r.Spec.Recovery[0].Checks[0].ID = "other-license"
			r.Spec.Recovery[0].Checks[0].Script = checkContract("other-license")
		}, "license check"},
		{"recovery-nonrequired-check", func(r *Release) {
			r.Spec.RequiredChecks = append(r.Spec.RequiredChecks, "license")
			r.Spec.Recovery[0].Checks[0].Required = false
		}, "license check"},
		{"recovery-different-material", func(r *Release) { r.Spec.Recovery[0].Checks[0].SecretRefs = []string{"other-license"} }, "license check"},
		{"recovery-wrong-domain", func(r *Release) { r.Spec.Recovery[0].Checks[0].Domain = "recovery" }, "license check"},
		{"recovery-nonzero-exit", func(r *Release) { r.Spec.Recovery[0].Checks[0].ExpectedExitCode = 1 }, "license check"},
		{"recovery-optional-image", func(r *Release) { r.Spec.Assets[3].Optional = true }, "image"},
		{"recovery-blank-command", func(r *Release) { r.Spec.Recovery[0].Checks[0].Command = []string{" "} }, "argv"},
		{"every-executable-recovery", func(r *Release) {
			r.Spec.Recovery = append(r.Spec.Recovery, Recovery{ID: "other", ToRelease: "0.9.0", Operations: []Operation{{ID: "restore", Type: "helm"}}})
		}, "license check"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := licensedScriptRelease()
			test.change(&r)
			assertContractResult(t, ValidateRelease(r), test.want)
		})
	}
}

func TestReleaseScriptSuccessCheckBounds(t *testing.T) {
	for _, count := range []int{64, 65} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r := classifiedScriptRelease()
			r.Spec.Operations[0].Script.SuccessChecks = nil
			for i := range count {
				check := r.Spec.Checks[0]
				check.ID = fmt.Sprintf("success-%d", i)
				r.Spec.Checks = append(r.Spec.Checks, check)
				r.Spec.Operations[0].Script.SuccessChecks = append(r.Spec.Operations[0].Script.SuccessChecks, check.ID)
			}
			err := ValidateRelease(r)
			if count == 64 {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "1..64 successChecks") {
				t.Fatalf("oversized successChecks: got %v", err)
			}
		})
	}
}

func TestReleaseContractsStrictDecode(t *testing.T) {
	r := licensedScriptRelease()
	r.Spec.Transitions[0].IntermediateReleases = []string{"1.1.0", "1.5.0"}
	direct := r.Spec.Transitions[0]
	direct.ID, direct.FromRelease, direct.IntermediateReleases = "direct", "1.5.0", nil
	r.Spec.Transitions = append(r.Spec.Transitions, direct)
	for _, format := range []struct {
		name   string
		encode func(any) ([]byte, error)
	}{
		{"json", json.Marshal},
		{"yaml", yaml.Marshal},
	} {
		t.Run(format.name, func(t *testing.T) {
			data, err := format.encode(r)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Release
			if err := Decode(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(r, decoded) {
				t.Fatal("contract declarations changed during strict decoding")
			}
			if err := ValidateRelease(decoded); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, document := range []string{
		`{"spec":{"operations":[{"script":{"inputs":"database"}}]}}`,
		`{"spec":{"operations":[{"script":{"retry":{"expression":"true"}}}]}}`,
		`{"spec":{"operations":[{"script":{"Retry":"manual"}}]}}`,
		`{"spec":{"operations":[{"script":{"grants":["cluster-admin"]}}]}}`,
		`{"spec":{"operations":[{"script":{"retry":"manual","retry":"retry-safe"}}]}}`,
		`{"spec":{"transitions":[{"intermediateReleases":"1.5.0"}]}}`,
		`{"spec":{"license":{"maxAgeSeconds":"3600"}}}`,
		`{"spec":{"license":{"MaxAgeSeconds":3600}}}`,
		`{"spec":{"license":{"check":{"expression":"valid"}}}}`,
		"spec:\n  operations:\n    - script:\n        grants: [cluster-admin]\n",
	} {
		var decoded Release
		if err := Decode([]byte(document), &decoded); err == nil {
			t.Errorf("malformed contract document accepted: %s", document)
		}
	}
	for _, test := range []struct {
		name   string
		change func(*Release)
		want   string
	}{
		{"missing-script", func(r *Release) { r.Spec.Operations[0].Script = nil }, "script contract"},
		{"unknown-retry", func(r *Release) { r.Spec.Operations[0].Script.Retry = "best-effort" }, "unknown retry"},
		{"invalid-route", func(r *Release) { r.Spec.Transitions[0].IntermediateReleases = []string{r.Metadata.Version} }, "intermediate"},
		{"invalid-age", func(r *Release) { r.Spec.License.MaxAgeSeconds = 0 }, "maxAgeSeconds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := licensedScriptRelease()
			test.change(&candidate)
			data, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Release
			if err := Decode(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if err := ValidateRelease(decoded); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("want %q validation error after decoding, got %v", test.want, err)
			}
		})
	}
}
