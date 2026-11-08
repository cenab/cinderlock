package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestReportEscapesLocalEvidenceAndRetainsGaps(t *testing.T) {
	r := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "run-1", State: "needs_reconciliation", Acceptance: "blocked", Error: "<script>alert(1)</script>", Domains: map[string]string{"integrity": "pass", "workflow": "blocked"}, Checks: []spec.CheckResult{{ID: "login", Required: true, Status: "blocked", Reason: "no approved browser path"}}}
	var b bytes.Buffer
	if err := Render(&b, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Skip to results", "not tested", "no approved browser path", "Do not repeat an uncertain migration", "scope=\"col\"", "&lt;script&gt;"} {
		if !strings.Contains(b.String(), want) {
			t.Fatal("missing report content", want)
		}
	}
	if strings.Contains(b.String(), "<script>alert(1)</script>") || strings.Contains(b.String(), "https://") {
		t.Fatal("active or remote HTML content present")
	}
	b.Reset()
	if err := Markdown(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "workflow | blocked") {
		t.Fatal(b.String())
	}
}

func TestReportRetainsApplicationObservations(t *testing.T) {
	zero, one, latency, memory := int64(0), int64(1), int64(17), int64(4096)
	observations := &spec.CheckObservations{
		Basis: "application_reported",
		Contract: spec.ObservationContract{Version: 1, TestRevision: "cpu-fixture-1", AssertionRevision: "budgets-1", Profile: "cpu-test", SampleCount: 1, Sampling: map[string]int64{"seed": 42}, Nondeterminism: "Scheduling varies latency.", Limitations: "Only one synthetic sample.", Metrics: []spec.MetricBound{
			{Name: "matched", Kind: "assertion", Unit: "count", Assertion: "<script>fixture criterion</script>", Min: &one, Max: &one},
			{Name: "latency", Kind: "latency", Unit: "microseconds", Assertion: "Application latency budget.", Min: &zero, Max: &latency},
			{Name: "memory", Kind: "resource", Unit: "bytes", Assertion: "Application memory budget.", Min: &zero, Max: &memory},
		}},
		Source: spec.ObservationSource{JobName: "check-job", JobUID: "job-uid", PodName: "original-pod", PodUID: "pod-uid", RecipeDigest: "recipe", OutputDigest: "output"},
		Report: &spec.ObservationReport{Version: 1, Profile: "cpu-test", Runtime: "runtime-1", Device: "cpu", Mode: "cpu", WarmCold: "warm", Concurrency: 1, Samples: []spec.ObservationSample{{Index: 1, Metrics: []spec.MetricValue{{Name: "matched", Unit: "count", Value: &one}, {Name: "latency", Unit: "microseconds", Value: &latency}, {Name: "memory", Unit: "bytes", Value: &memory}}}}},
	}
	observations.Contract.Sampling["<script>sampling</script>"] = 1
	run := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "observed-run", Checks: []spec.CheckResult{{ID: "inference", Domain: "workflow", Required: true, Status: "pass", Observations: observations}}}
	for name, render := range map[string]func(*bytes.Buffer) error{
		"html":     func(b *bytes.Buffer) error { return Render(b, run) },
		"markdown": func(b *bytes.Buffer) error { return Markdown(b, run) },
	} {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			if err := render(&b); err != nil {
				t.Fatal(err)
			}
			for _, value := range []string{"cpu-fixture-1", "budgets-1", "cpu-test", "seed", "42", "Scheduling varies latency.", "Only one synthetic sample.", "fixture criterion", "runtime-1", "microseconds", "17", "4096"} {
				if !strings.Contains(b.String(), value) {
					t.Fatalf("observation evidence omitted: %q", value)
				}
			}
			if strings.Contains(b.String(), "<script>") {
				t.Fatal("application declaration rendered as active content")
			}
		})
	}
	var b bytes.Buffer
	if err := JSON(&b, run); err != nil {
		t.Fatal(err)
	}
	var roundTrip spec.RunResult
	if err := spec.Decode(b.Bytes(), &roundTrip); err != nil {
		t.Fatal(err)
	}
	if *roundTrip.Checks[0].Observations.Report.Samples[0].Metrics[1].Value != latency || roundTrip.Checks[0].Observations.Source.PodUID != "pod-uid" {
		t.Fatal("JSON report lost typed values or original source identity")
	}
}

func TestMarkdownTreatsApplicationObservationTextAsLiteral(t *testing.T) {
	run := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "observed-run", Checks: []spec.CheckResult{{ID: "inference", Observations: &spec.CheckObservations{Contract: spec.ObservationContract{Limitations: "![private observation](https://tracking.invalid/pixel) and `raw` **text**"}}}}}
	var b bytes.Buffer
	if err := Markdown(&b, run); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "![private observation](") || strings.Contains(b.String(), "`raw`") || strings.Contains(b.String(), "**text**") || !strings.Contains(b.String(), "private observation") {
		t.Fatal("application observation text became Markdown formatting or an image request")
	}
}

func TestReportAssessesMatchingMetricsWithInclusiveBounds(t *testing.T) {
	low, high, above := int64(10), int64(20), int64(21)
	contract := spec.ObservationContract{Metrics: []spec.MetricBound{{Name: "latency", Unit: "microseconds", Min: &low, Max: &high}}}
	for _, test := range []struct {
		metric spec.MetricValue
		want   string
	}{
		{spec.MetricValue{Name: "latency", Unit: "microseconds", Value: &low}, "within bounds"},
		{spec.MetricValue{Name: "latency", Unit: "microseconds", Value: &high}, "within bounds"},
		{spec.MetricValue{Name: "latency", Unit: "microseconds", Value: &above}, "outside bounds"},
		{spec.MetricValue{Name: "latency", Unit: "milliseconds", Value: &low}, "not assessed"},
		{spec.MetricValue{Name: "other", Unit: "microseconds", Value: &low}, "not assessed"},
		{spec.MetricValue{Name: "latency", Unit: "microseconds"}, "not assessed"},
	} {
		run := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "assessment", Checks: []spec.CheckResult{{ID: "check", Observations: &spec.CheckObservations{Contract: contract, Report: &spec.ObservationReport{Samples: []spec.ObservationSample{{Index: 1, Metrics: []spec.MetricValue{test.metric}}}}}}}}
		var out bytes.Buffer
		if err := Markdown(&out, run); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), test.want) {
			t.Fatalf("reported metric did not retain its %q assessment", test.want)
		}
	}
}
