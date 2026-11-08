package state

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestOversizedResultPreservesReadableRunAndEvents(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.CreateRun(ctx, fixtureRun("run")); err != nil {
		t.Fatal(err)
	}
	result := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "run", State: "verifying", Error: "prior readable evidence"}
	if err := s.SetState(ctx, "run", "verifying", true, result); err != nil {
		t.Fatal(err)
	}
	before, err := s.Run(ctx, "run")
	if err != nil {
		t.Fatal(err)
	}
	events, err := s.Events(ctx, "run")
	if err != nil {
		t.Fatal(err)
	}
	oversized := result
	oversized.Error = "PRIVATE-RESULT-MARKER" + strings.Repeat("x", spec.MaxDocumentBytes)
	body, err := json.Marshal(oversized)
	if err != nil {
		t.Fatal(err)
	}
	var decoded spec.RunResult
	if err := spec.Decode(body, &decoded); err == nil {
		t.Fatal("fixture does not exceed the result reader's limit")
	}
	if err := s.SetState(ctx, "run", "succeeded", false, oversized); err == nil {
		t.Fatal("oversized unreadable result replaced the active run")
	} else if strings.Contains(err.Error(), "PRIVATE-RESULT-MARKER") {
		t.Fatal("size rejection disclosed result data")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s = reopened
	after, err := s.Run(ctx, "run")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("size rejection changed the durable run or its prior result", err)
	}
	if err := spec.Decode(after.Result, &decoded); err != nil || decoded.Error != result.Error {
		t.Fatal("prior result is no longer readable", err)
	}
	afterEvents, err := s.Events(ctx, "run")
	if err != nil || !reflect.DeepEqual(events, afterEvents) {
		t.Fatal("size rejection changed the event journal", err)
	}
	result.State, result.Error = "succeeded", ""
	if err := s.SetState(ctx, "run", "succeeded", false, result); err != nil {
		t.Fatal("smaller result was rejected after an oversized update", err)
	}
	after, err = s.Run(ctx, "run")
	if err != nil || after.Active || after.State != "succeeded" {
		t.Fatal("smaller result did not commit the requested run state", err)
	}
	var finalResult spec.RunResult
	if err := spec.Decode(after.Result, &finalResult); err != nil || !reflect.DeepEqual(result, finalResult) {
		t.Fatal("smaller result did not survive reader round trip", err)
	}
	afterEvents, err = s.Events(ctx, "run")
	if err != nil || len(afterEvents) != len(events)+1 || afterEvents[len(events)].Type != "run_state" {
		t.Fatal("smaller result did not append exactly one state event", err)
	}
}

func TestResultAtReaderSizeLimitIsStoredAndReadable(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateRun(ctx, fixtureRun("run")); err != nil {
		t.Fatal(err)
	}
	result := spec.RunResult{Header: spec.NewHeader("RunResult"), RunID: "run", State: "succeeded", Error: "x"}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	result.Error = strings.Repeat("x", spec.MaxDocumentBytes-len(body)+1)
	if err := s.SetState(ctx, "run", "succeeded", false, result); err != nil {
		t.Fatal("result at the reader's inclusive size limit was rejected", err)
	}
	stored, err := s.Run(ctx, "run")
	if err != nil || len(stored.Result) != spec.MaxDocumentBytes {
		t.Fatal("fixture or stored result differs from the exact size limit", err)
	}
	var decoded spec.RunResult
	if err := spec.Decode(stored.Result, &decoded); err != nil || !reflect.DeepEqual(result, decoded) {
		t.Fatal("result at the size limit did not survive reader round trip", err)
	}
}
