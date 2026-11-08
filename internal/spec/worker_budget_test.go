package spec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAuthoredWorkersRejectMissingResourceBudget(t *testing.T) {
	const script = `"script":{"inputs":["locked image and explicit argv"],"permissions":["synthetic application only"],"sideEffects":["declared fixture writes"],"successChecks":["workflow"],"retry":"retry-safe"}`
	var operation Operation
	if err := Decode([]byte(`{"id":"migration","type":"migrate","image":"runner","command":["/app/migrate"],"idempotent":true,"timeoutSeconds":30,`+script+`}`), &operation); err != nil {
		t.Fatal(err)
	}
	t.Run("operation", func(t *testing.T) {
		if err := ValidateOperation(operation); err == nil || !strings.Contains(err.Error(), "resource") {
			t.Fatalf("authored operation without resource budget accepted: %v", err)
		}
	})
	var check Check
	if err := Decode([]byte(`{"id":"workflow","type":"job","domain":"workflow","image":"runner","command":["/app/verify"],"required":true,"timeoutSeconds":30,`+script+`}`), &check); err != nil {
		t.Fatal(err)
	}
	t.Run("check", func(t *testing.T) {
		if err := ValidateCheck(check); err == nil || !strings.Contains(err.Error(), "resource") {
			t.Fatalf("authored check without resource budget accepted: %v", err)
		}
	})
}

func TestAuthoredWorkerResourceProfile(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*ScriptContract)
		want   string
	}{
		{"minimum", func(s *ScriptContract) {
			s.Resources = &WorkerResources{CPUMillis: 1, MemoryBytes: 1, EphemeralStorageBytes: 1, TemporaryBytes: 1}
		}, ""},
		{"maximum", func(s *ScriptContract) {
			s.Resources = &WorkerResources{CPUMillis: 64000, MemoryBytes: 1 << 40, EphemeralStorageBytes: 1 << 40, TemporaryBytes: 1 << 40}
		}, ""},
		{"missing", func(s *ScriptContract) { s.Resources = nil }, "resources"},
		{"zero-cpu", func(s *ScriptContract) { s.Resources.CPUMillis = 0 }, "cpuMillis"},
		{"negative-cpu", func(s *ScriptContract) { s.Resources.CPUMillis = -1 }, "cpuMillis"},
		{"large-cpu", func(s *ScriptContract) { s.Resources.CPUMillis = 64001 }, "cpuMillis"},
		{"zero-memory", func(s *ScriptContract) { s.Resources.MemoryBytes = 0 }, "memoryBytes"},
		{"negative-memory", func(s *ScriptContract) { s.Resources.MemoryBytes = -1 }, "memoryBytes"},
		{"large-memory", func(s *ScriptContract) { s.Resources.MemoryBytes = 1<<40 + 1 }, "memoryBytes"},
		{"zero-ephemeral", func(s *ScriptContract) { s.Resources.EphemeralStorageBytes = 0 }, "ephemeralStorageBytes"},
		{"negative-ephemeral", func(s *ScriptContract) { s.Resources.EphemeralStorageBytes = -1 }, "ephemeralStorageBytes"},
		{"large-ephemeral", func(s *ScriptContract) { s.Resources.EphemeralStorageBytes = 1<<40 + 1 }, "ephemeralStorageBytes"},
		{"zero-temporary", func(s *ScriptContract) { s.Resources.TemporaryBytes = 0 }, "temporaryBytes"},
		{"negative-temporary", func(s *ScriptContract) { s.Resources.TemporaryBytes = -1 }, "temporaryBytes"},
		{"large-temporary", func(s *ScriptContract) { s.Resources.TemporaryBytes = 1<<40 + 1 }, "temporaryBytes"},
		{"temporary-exceeds-ephemeral", func(s *ScriptContract) { s.Resources.TemporaryBytes = s.Resources.EphemeralStorageBytes + 1 }, "temporaryBytes"},
		{"gpu", func(s *ScriptContract) { s.Resources.GPUCount = 1 }, "gpuCount"},
		{"negative-gpu", func(s *ScriptContract) { s.Resources.GPUCount = -1 }, "gpuCount"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, kind := range []string{"job", "migrate", "backup", "reindex", "seed", "check"} {
				t.Run(kind, func(t *testing.T) {
					r := classifiedScriptRelease()
					test.change(r.Spec.Operations[0].Script)
					op := r.Spec.Operations[0]
					if kind == "check" {
						check := r.Spec.Checks[0]
						check.Script = op.Script
						body, err := json.Marshal(check)
						if err != nil {
							t.Fatal(err)
						}
						if err := Decode(body, &check); err != nil {
							t.Fatal(err)
						}
						assertContractResult(t, ValidateCheck(check), test.want)
						return
					}
					op.Type = kind
					body, err := json.Marshal(op)
					if err != nil {
						t.Fatal(err)
					}
					if err := Decode(body, &op); err != nil {
						t.Fatal(err)
					}
					assertContractResult(t, ValidateOperation(op), test.want)
				})
			}
		})
	}
}

func TestAuthoredWorkerTimeoutProfile(t *testing.T) {
	for _, timeout := range []int64{0, -1, 86401, 1, 86400} {
		for _, kind := range []string{"job", "migrate", "backup", "reindex", "seed", "check"} {
			op := classifiedScriptRelease().Spec.Operations[0]
			op.TimeoutSeconds = timeout
			want := ""
			if timeout < 1 || timeout > 86400 {
				want = "timeout"
			}
			if kind == "check" {
				check := Check{ID: "workflow", Type: "job", Domain: "workflow", Image: op.Image, Command: op.Command, Script: op.Script, TimeoutSeconds: timeout}
				assertContractResult(t, ValidateCheck(check), want)
			} else {
				op.Type = kind
				assertContractResult(t, ValidateOperation(op), want)
			}
		}
	}
}

func TestAuthoredOperationRejectsNodeAndGPUOverrides(t *testing.T) {
	for _, change := range []func(*Operation){
		func(o *Operation) { o.NodeName = "gpu-node" },
		func(o *Operation) { o.NodeUID = "node-uid" },
		func(o *Operation) { o.GPUCount = 1 },
		func(o *Operation) { o.GPUCount = -1 },
	} {
		op := classifiedScriptRelease().Spec.Operations[0]
		change(&op)
		assertContractResult(t, ValidateOperation(op), "unsupported")
	}
}

func TestWorkerResourcesStrictDecode(t *testing.T) {
	for _, resources := range []string{
		`{"cpu":"100m"}`, `{"memory":"64Mi"}`, `{"ephemeral-storage":"64Mi"}`,
		`{"cpuMillis":"100m"}`, `{"memoryBytes":"64Mi"}`, `{"cpuMillis":0.5}`,
		`{"requests":{"cpu":"100m"}}`, `{"limits":{"memory":"64Mi"}}`,
		`{"nvidia.com/gpu":1}`, `{"extendedResources":{"vendor/device":1}}`,
		`{"CPUMillis":100}`, `{"cpuMillis":100,"cpuMillis":200}`,
	} {
		var script ScriptContract
		if err := Decode([]byte(`{"resources":`+resources+`}`), &script); err == nil {
			t.Errorf("unsupported worker resources decoded: %s", resources)
		}
	}
	for _, document := range []string{
		"resources:\n  cpu: 100m\n", "resources:\n  memoryBytes: 64Mi\n",
		"resources:\n  nvidia.com/gpu: 1\n", "resources:\n  cpuMillis: 1.5\n",
	} {
		var script ScriptContract
		if err := Decode([]byte(document), &script); err == nil {
			t.Errorf("unsupported YAML worker resources decoded: %s", document)
		}
	}
}
