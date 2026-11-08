package state

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestReceiverBindingIsDurableSingleAttachAndTransactional(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateRun(ctx, fixtureRun("native")); err != nil {
		t.Fatal(err)
	}
	op, err := s.Intent(ctx, "native", "seed", map[string]string{"type": "seed"}, "job")
	if err != nil {
		t.Fatal(err)
	}
	w := Worker{RunID: "native", StepID: "seed", Attempt: op.Attempt, Role: "seed", Name: "job", UID: "job-uid", RecipeDigest: "recipe"}
	if err = s.BindWorker(ctx, w); err != nil {
		t.Fatal(err)
	}
	r := ModelReceiver{Worker: w, PodName: "pod", PodUID: "pod-uid", RecipeDigest: "recipe"}
	wrong := r
	wrong.Worker.UID = "replacement"
	if err = s.BindModelReceiver(ctx, wrong); err == nil {
		t.Fatal("replacement Job bound receiver")
	}
	if _, err = s.db.ExecContext(ctx, `CREATE TRIGGER reject_receiver_event BEFORE INSERT ON events WHEN NEW.type='model_receiver_bound' BEGIN SELECT RAISE(ABORT,'event failed'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.BindModelReceiver(ctx, r); err == nil {
		t.Fatal("binding committed without event")
	}
	if _, err = s.ModelReceiver(ctx, w); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("failed transaction left binding: %v", err)
	}
	if _, err = s.db.ExecContext(ctx, `DROP TRIGGER reject_receiver_event`); err != nil {
		t.Fatal(err)
	}
	if err = s.BindModelReceiver(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err = s.BindModelReceiver(ctx, r); err == nil {
		t.Fatal("same Pod allowed a second attachment")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.ModelReceiver(ctx, w)
	if err != nil || got.PodUID != r.PodUID || got.RecipeDigest != r.RecipeDigest {
		t.Fatalf("receiver binding lost: %#v %v", got, err)
	}
}
