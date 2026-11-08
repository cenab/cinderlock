package spec

import (
	"fmt"
	"strings"
	"testing"
)

func TestReleaseRejectsOversizedAggregateObservationEvidence(t *testing.T) {
	contract, _ := observationFixture(t)
	contract.SampleCount = 32
	zero, one := int64(0), int64(1)
	for i := 3; i < 16; i++ {
		contract.Metrics = append(contract.Metrics, MetricBound{Name: fmt.Sprintf("metric-%s-%d", strings.Repeat("m", 30), i), Kind: "resource", Unit: "bytes", Assertion: strings.Repeat("Declared measurement. ", 20), Min: &zero, Max: &one})
	}
	base := Check{ID: "workflow", Type: "job", Domain: "workflow", Required: true, Image: "runner", Command: []string{"/check"}, ObservationContract: &contract}
	release := Release{Header: NewHeader("Release"), Spec: ReleaseSpec{Profile: "cpu-test", Deployment: Deployment{Type: "helm", Chart: "chart.tgz"}, Assets: []Asset{{ID: "runner", Type: "image", Source: "oci:./image#1"}}, Operations: []Operation{{ID: "deploy", Type: "helm"}}, Checks: []Check{base}, RequiredChecks: []string{"workflow"}, Recovery: []Recovery{{ID: "restore", ToRelease: "2.0.0", Operations: []Operation{{ID: "restart", Type: "restart", Service: "api"}}, Checks: []Check{base}}}, Transitions: []Transition{{ID: "upgrade", FromRelease: "1.0.0", Operations: []string{"deploy"}, Recovery: "restore"}}}}
	release.Metadata = Metadata{Application: "fixture", Version: "2.0.0", Channel: "stable", Sequence: 2}
	if err := ValidateRelease(release); err != nil {
		t.Fatal("small positive declaration rejected:", err)
	}
	var oversized []Check
	for i := 0; i < 400; i++ {
		check := base
		check.ID = fmt.Sprintf("observed-%d", i)
		oversized = append(oversized, check)
	}
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery-%t", recovery), func(t *testing.T) {
			candidate := release
			if recovery {
				candidate.Spec.Recovery = append([]Recovery(nil), release.Spec.Recovery...)
				candidate.Spec.Recovery[0].Checks = oversized
			} else {
				candidate.Spec.Checks = append([]Check{base}, oversized...)
			}
			if err := ValidateRelease(candidate); err == nil || !strings.Contains(err.Error(), "aggregate observation") {
				t.Fatalf("individually valid checks can produce an unreadable aggregate result: %v", err)
			}
		})
	}
}

func observationFixture(t *testing.T) (ObservationContract, string) {
	t.Helper()
	var contract ObservationContract
	if err := Decode([]byte(`{"version":1,"testRevision":"fixture-1","assertionRevision":"bounds-1","profile":"cpu-test","sampleCount":1,"sampling":{"seed":42},"nondeterminism":"Scheduling varies latency despite the seed.","limitations":"One synthetic sample cannot establish production capacity.","metrics":[{"name":"matched","kind":"assertion","unit":"count","assertion":"Required fixture matched.","min":1,"max":1},{"name":"latency","kind":"latency","unit":"milliseconds","assertion":"Request meets the latency budget.","min":0,"max":100},{"name":"memory","kind":"resource","unit":"bytes","assertion":"Reported allocation meets the memory budget.","min":0,"max":4096}]}`), &contract); err != nil {
		t.Fatal(err)
	}
	digest, err := Digest(contract)
	if err != nil {
		t.Fatal(err)
	}
	return contract, `{"version":1,"contractDigest":"` + digest + `","profile":"cpu-test","runtime":"python-3.14","device":"cpu","mode":"cpu","warmCold":"warm","concurrency":1,"samples":[{"index":1,"metrics":[{"name":"matched","unit":"count","value":1},{"name":"latency","unit":"milliseconds","value":100},{"name":"memory","unit":"bytes","value":4096}]}]}`
}

func TestObservationDocumentRejectsNonContractData(t *testing.T) {
	contract, valid := observationFixture(t)
	report, passed, err := EvaluateObservations(contract, []byte(valid))
	if err != nil || !passed || report == nil || *report.Samples[0].Metrics[1].Value != 100 || *report.Samples[0].Metrics[2].Value != 4096 {
		t.Fatalf("inclusive bounds rejected: %#v %t %v", report, passed, err)
	}
	for name, output := range map[string]string{
		"empty":            "",
		"yaml":             "version: 1",
		"flow_yaml":        strings.Replace(valid, `"runtime":`, `runtime:`, 1),
		"malformed":        `{"SYNTHETIC-SECRET":`,
		"oversized":        strings.Repeat(" ", MaxObservationBytes) + valid,
		"trailing":         valid + "{}",
		"unknown":          strings.Replace(valid, `"runtime":`, `"SYNTHETIC-SECRET":"prompt","runtime":`, 1),
		"duplicate_key":    strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"cased_field":      strings.Replace(valid, `"profile":`, `"Profile":`, 1),
		"wrong_contract":   strings.Replace(valid, `"contractDigest":"sha256:`, `"contractDigest":"sha256:0`, 1),
		"wrong_version":    strings.Replace(valid, `"version":1`, `"version":2`, 1),
		"wrong_profile":    strings.Replace(valid, `"profile":"cpu-test"`, `"profile":"other"`, 1),
		"missing_runtime":  strings.Replace(valid, `"runtime":"python-3.14",`, "", 1),
		"raw_device":       strings.Replace(valid, `"device":"cpu"`, `"device":"<SYNTHETIC-SECRET>"`, 1),
		"invalid_warmth":   strings.Replace(valid, `"warmCold":"warm"`, `"warmCold":"hot"`, 1),
		"no_concurrency":   strings.Replace(valid, `"concurrency":1`, `"concurrency":0`, 1),
		"too_concurrent":   strings.Replace(valid, `"concurrency":1`, `"concurrency":1025`, 1),
		"sample_index":     strings.Replace(valid, `"index":1`, `"index":2`, 1),
		"missing_metric":   strings.Replace(valid, `,{"name":"memory","unit":"bytes","value":4096}`, "", 1),
		"extra_metric":     strings.Replace(valid, `"metrics":[`, `"metrics":[{"name":"extra","unit":"count","value":0},`, 1),
		"duplicate_metric": strings.Replace(valid, `"name":"memory"`, `"name":"latency"`, 1),
		"unit_changed":     strings.Replace(valid, `"unit":"milliseconds"`, `"unit":"microseconds"`, 1),
		"missing_value":    strings.Replace(valid, `,"value":1`, "", 1),
		"null_value":       strings.Replace(valid, `"value":1`, `"value":null`, 1),
		"unknown_nested":   strings.Replace(valid, `"value":1`, `"value":1,"raw":"SYNTHETIC-SECRET"`, 1),
		"float":            strings.Replace(valid, `"value":1`, `"value":1.0`, 1),
		"exponent":         strings.Replace(valid, `"value":1`, `"value":1e0`, 1),
		"unsafe_integer":   strings.Replace(valid, `"value":1`, `"value":9007199254740992`, 1),
		"overflow_integer": strings.Replace(valid, `"value":1`, `"value":9223372036854775808`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			report, passed, err := EvaluateObservations(contract, []byte(output))
			if err == nil || passed || report != nil || strings.Contains(err.Error(), "SYNTHETIC-SECRET") {
				t.Fatalf("invalid document accepted or disclosed: report=%#v passed=%t error=%v", report, passed, err)
			}
		})
	}
	for _, samples := range [][]ObservationSample{nil, {report.Samples[0], {Index: 2, Metrics: report.Samples[0].Metrics}}} {
		changed := *report
		changed.Samples = samples
		output, err := Canonical(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, passed, err := EvaluateObservations(contract, output); err == nil || passed {
			t.Fatalf("sample count mismatch accepted: %d", len(samples))
		}
	}
}

func TestObservationReportsPreserveUnknownOrMixedCacheState(t *testing.T) {
	contract, valid := observationFixture(t)
	for _, state := range []string{"unknown", "mixed"} {
		output := strings.Replace(valid, `"warmCold":"warm"`, `"warmCold":"`+state+`"`, 1)
		report, passed, err := EvaluateObservations(contract, []byte(output))
		if err != nil || !passed || report == nil || report.WarmCold != state {
			t.Fatalf("explicit %s state was lost or required a guessed cache claim: %v", state, err)
		}
	}
}

func TestValidateCheckRequiresBoundedObservationDeclarations(t *testing.T) {
	for name, mutate := range map[string]func(*Check){
		"http":               func(c *Check) { c.Type, c.URL, c.ExpectedStatus = "http", "https://app.invalid", 200 },
		"exit_code":          func(c *Check) { c.ExpectedExitCode = 1 },
		"timeout":            func(c *Check) { c.TimeoutSeconds = 86401 },
		"version":            func(c *Check) { c.ObservationContract.Version = 0 },
		"test_revision":      func(c *Check) { c.ObservationContract.TestRevision = "" },
		"assertion_revision": func(c *Check) { c.ObservationContract.AssertionRevision = "" },
		"sample_limit":       func(c *Check) { c.ObservationContract.SampleCount = 33 },
		"sampling":           func(c *Check) { c.ObservationContract.Sampling = nil },
		"unsafe_setting":     func(c *Check) { c.ObservationContract.Sampling["seed"] = 9007199254740992 },
		"nondeterminism":     func(c *Check) { c.ObservationContract.Nondeterminism = "" },
		"limitations":        func(c *Check) { c.ObservationContract.Limitations = "" },
		"prose_limit":        func(c *Check) { c.ObservationContract.Limitations = strings.Repeat("x", 1025) },
		"control_text":       func(c *Check) { c.ObservationContract.Nondeterminism = "line\nline" },
		"duplicate_metric":   func(c *Check) { c.ObservationContract.Metrics[1].Name = c.ObservationContract.Metrics[0].Name },
		"unknown_kind":       func(c *Check) { c.ObservationContract.Metrics[1].Kind = "quality" },
		"missing_resource": func(c *Check) {
			c.ObservationContract.Metrics[2].Kind, c.ObservationContract.Metrics[2].Unit = "assertion", "count"
		},
		"changed_unit":      func(c *Check) { c.ObservationContract.Metrics[1].Unit = "seconds" },
		"missing_min":       func(c *Check) { c.ObservationContract.Metrics[0].Min = nil },
		"missing_max":       func(c *Check) { c.ObservationContract.Metrics[0].Max = nil },
		"unsafe_bound":      func(c *Check) { *c.ObservationContract.Metrics[0].Max = 9007199254740992 },
		"reversed_bound":    func(c *Check) { *c.ObservationContract.Metrics[1].Min = 101 },
		"negative_resource": func(c *Check) { *c.ObservationContract.Metrics[2].Min = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			contract, _ := observationFixture(t)
			check := Check{ID: "inference", Type: "job", Domain: "workflow", Image: "runner", Command: []string{"/app/test"}, ObservationContract: &contract}
			if err := ValidateCheck(check); err != nil {
				t.Fatal(err)
			}
			mutate(&check)
			if err := ValidateCheck(check); err == nil {
				t.Fatal("invalid observation declaration accepted")
			}
		})
	}
}
