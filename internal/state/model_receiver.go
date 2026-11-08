package state

import (
	"context"
	"errors"
)

type ModelReceiver struct {
	Worker       Worker `json:"worker"`
	PodName      string `json:"podName"`
	PodUID       string `json:"podUID"`
	RecipeDigest string `json:"recipeDigest"`
}

func (s *Store) modelReceiverTable(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS model_receivers(run_id TEXT NOT NULL,step_id TEXT NOT NULL,attempt INTEGER NOT NULL,role TEXT NOT NULL,job_uid TEXT NOT NULL,pod_name TEXT NOT NULL,pod_uid TEXT NOT NULL,recipe_digest TEXT NOT NULL,PRIMARY KEY(run_id,step_id,attempt,role),FOREIGN KEY(run_id,step_id,attempt,role) REFERENCES workers(run_id,step_id,attempt,role));`)
	return err
}

func (s *Store) BindModelReceiver(ctx context.Context, r ModelReceiver) error {
	if r.PodName == "" || r.PodUID == "" || r.RecipeDigest == "" {
		return errors.New("model receiver needs a server Pod identity and recipe")
	}
	if err := s.modelReceiverTable(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var uid, recipe, status string
	if err = tx.QueryRowContext(ctx, `SELECT w.uid,w.recipe_digest,o.state FROM workers w JOIN operations o ON w.run_id=o.run_id AND w.step_id=o.step_id AND w.attempt=o.attempt WHERE w.run_id=? AND w.step_id=? AND w.attempt=? AND w.role=?`, r.Worker.RunID, r.Worker.StepID, r.Worker.Attempt, r.Worker.Role).Scan(&uid, &recipe, &status); err != nil {
		return err
	}
	if uid != r.Worker.UID || recipe != r.Worker.RecipeDigest || recipe != r.RecipeDigest || (status != "intent" && status != "uncertain") {
		return errors.New("model receiver differs from its unresolved worker intent")
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO model_receivers(run_id,step_id,attempt,role,job_uid,pod_name,pod_uid,recipe_digest) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(run_id,step_id,attempt,role) DO NOTHING`, r.Worker.RunID, r.Worker.StepID, r.Worker.Attempt, r.Worker.Role, r.Worker.UID, r.PodName, r.PodUID, r.RecipeDigest)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("model receiver was already bound; an attachment cannot be retried")
	}
	if err = appendEvent(ctx, tx, r.Worker.RunID, "model_receiver_bound", r); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ModelReceiver(ctx context.Context, w Worker) (ModelReceiver, error) {
	if err := s.modelReceiverTable(ctx); err != nil {
		return ModelReceiver{}, err
	}
	r := ModelReceiver{Worker: w}
	var jobUID string
	err := s.db.QueryRowContext(ctx, `SELECT job_uid,pod_name,pod_uid,recipe_digest FROM model_receivers WHERE run_id=? AND step_id=? AND attempt=? AND role=?`, w.RunID, w.StepID, w.Attempt, w.Role).Scan(&jobUID, &r.PodName, &r.PodUID, &r.RecipeDigest)
	if err != nil {
		return r, err
	}
	if jobUID != w.UID {
		return r, errors.New("model receiver Job UID changed")
	}
	return r, nil
}
