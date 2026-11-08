package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestClusterJournalKeepsCompleteLargeObservationsLocally(t *testing.T) {
	e, client, _ := fixture(t)
	ctx := context.Background()
	contract := observationContract()
	contract.SampleCount = 32
	zero, one := int64(0), int64(1)
	for len(contract.Metrics) < 16 {
		contract.Metrics = append(contract.Metrics, spec.MetricBound{Kind: "resource", Unit: "bytes"})
	}
	for i := range contract.Metrics {
		metric := &contract.Metrics[i]
		metric.Name = fmt.Sprintf("metric-%s-%d", strings.Repeat("m", 30), i)
		metric.Assertion, metric.Min, metric.Max = strings.Repeat("Declared scope. ", 30), &zero, &one
	}
	report := spec.ObservationReport{Version: 1, ContractDigest: mustDigest(t, contract), Profile: contract.Profile, Runtime: "fixture", Device: "cpu", Mode: "cpu", WarmCold: "unknown", Concurrency: 1}
	for i := 0; i < contract.SampleCount; i++ {
		sample := spec.ObservationSample{Index: i + 1}
		for _, metric := range contract.Metrics {
			sample.Metrics = append(sample.Metrics, spec.MetricValue{Name: metric.Name, Unit: metric.Unit, Value: &one})
		}
		report.Samples = append(report.Samples, sample)
	}
	output, err := spec.Canonical(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, passed, err := spec.EvaluateObservations(*contract, output); err != nil || !passed {
		t.Fatal("large individual report must fit its declared profile", err)
	}
	result := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "large-observations", PlanDigest: spec.Hash([]byte("plan")), State: "succeeded", Acceptance: "pass", Domains: map[string]string{"integrity": "pass", "readiness": "pass", "workflow": "pass", "recovery": "not_tested"}}
	for i := 0; i < 8; i++ {
		result.Checks = append(result.Checks, spec.CheckResult{ID: fmt.Sprintf("check-%d", i), Status: "pass", Required: true, Domain: "workflow", Observations: &spec.CheckObservations{Basis: "application_reported", Contract: *contract, Report: &report}})
	}
	body, err := json.Marshal(result)
	if err != nil || len(body) <= 256<<10 {
		t.Fatal("fixture does not reproduce aggregate cluster-journal overflow", len(body), err)
	}
	if err := e.Store.CreateRun(ctx, state.Run{ID: result.RunID, Application: "app", Namespace: "test", TargetID: "target", PlanDigest: result.PlanDigest, Plan: []byte(`{}`), Site: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if err := e.clusterRecord(ctx, result.RunID, result.PlanDigest, result.State, result); err != nil {
		t.Fatal("individually valid observations prevented result finalization:", err)
	}
	if err := e.Store.SetState(ctx, result.RunID, result.State, false, result); err != nil {
		t.Fatal(err)
	}
	run, err := e.Store.Run(ctx, result.RunID)
	if err != nil || string(run.Result) != string(body) {
		t.Fatal("complete local evidence was truncated", err)
	}
	cm, err := client.CoreV1().ConfigMaps("test").Get(ctx, "cinderlock-run-"+result.RunID, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Kind         string `json:"kind"`
		ResultDigest string `json:"resultDigest"`
		CheckCount   int    `json:"checkCount"`
		PassedChecks int    `json:"passedChecks"`
	}
	if err := json.Unmarshal([]byte(cm.Data["operation"]), &summary); err != nil || summary.Kind != "RunJournalSummary" || summary.ResultDigest != spec.Hash(run.Result) || summary.CheckCount != len(result.Checks) || summary.PassedChecks != len(result.Checks) || len(cm.Data["operation"]) >= 256<<10 {
		t.Fatal("bounded cluster summary lost local-result identity or status", summary, err)
	}
	if err := e.clusterRecord(ctx, result.RunID, result.PlanDigest, "intent", map[string]string{"payload": strings.Repeat("x", 300<<10)}); err == nil {
		t.Fatal("large arbitrary intents bypassed the unchanged journal limit")
	}
}
