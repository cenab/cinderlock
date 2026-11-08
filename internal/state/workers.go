package state

import (
	"context"
	"errors"
)

// Worker records a server-assigned identity after creation and before waiting
// for any terminal outcome. A name alone cannot reconcile a replacement Job.
type Worker struct {
	RunID        string `json:"runID"`
	StepID       string `json:"stepID"`
	Attempt      int    `json:"attempt"`
	Role         string `json:"role"`
	Name         string `json:"name"`
	UID          string `json:"uid"`
	RecipeDigest string `json:"recipeDigest"`
	CreatedAt    string `json:"createdAt"`
}

func (s *Store) WorkerProtocol(ctx context.Context, runID string) error {
	var protocol string
	if err := s.db.QueryRowContext(ctx, `SELECT worker_protocol FROM run_protocols WHERE run_id=?`, runID).Scan(&protocol); err != nil {
		return errors.New("run predates durable server-UID worker identity; explicit external reconciliation is required")
	}
	if protocol != "server-uid-v1" {
		return errors.New("unsupported worker identity protocol")
	}
	return nil
}

func (s *Store) LatestOperation(ctx context.Context, runID, stepID string) (Operation, error) {
	var o Operation
	var evidence []byte
	err := s.db.QueryRowContext(ctx, `SELECT run_id,step_id,attempt,state,intent_json,evidence_json,external_id,updated_at FROM operations WHERE run_id=? AND step_id=? ORDER BY attempt DESC LIMIT 1`, runID, stepID).Scan(&o.RunID, &o.StepID, &o.Attempt, &o.State, &o.Intent, &evidence, &o.ExternalID, &o.UpdatedAt)
	o.Evidence = evidence
	return o, err
}

func (s *Store) BindWorker(ctx context.Context, w Worker) error {
	if w.RunID == "" || w.StepID == "" || w.Attempt < 1 || w.Role == "" || w.Name == "" || w.UID == "" || w.RecipeDigest == "" {
		return errors.New("incomplete worker identity")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM operations WHERE run_id=? AND step_id=? AND attempt=?`, w.RunID, w.StepID, w.Attempt).Scan(&status); err != nil {
		return err
	}
	if status != "intent" && status != "uncertain" {
		return errors.New("worker needs an unresolved durable operation intent")
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO workers(run_id,step_id,attempt,role,name,uid,recipe_digest,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(run_id,step_id,attempt,role) DO NOTHING`, w.RunID, w.StepID, w.Attempt, w.Role, w.Name, w.UID, w.RecipeDigest, now())
	if err != nil {
		return err
	}
	var name, uid, recipe string
	if err := tx.QueryRowContext(ctx, `SELECT name,uid,recipe_digest FROM workers WHERE run_id=? AND step_id=? AND attempt=? AND role=?`, w.RunID, w.StepID, w.Attempt, w.Role).Scan(&name, &uid, &recipe); err != nil {
		return err
	}
	if name != w.Name || uid != w.UID || recipe != w.RecipeDigest {
		return errors.New("worker identity already binds a different resource or recipe")
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		if err := appendEvent(ctx, tx, w.RunID, "worker_bound", map[string]any{"stepID": w.StepID, "attempt": w.Attempt, "role": w.Role, "name": w.Name, "uid": w.UID, "recipeDigest": w.RecipeDigest}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Worker(ctx context.Context, runID, stepID string, attempt int, role string) (Worker, error) {
	return scanWorker(s.db.QueryRowContext(ctx, `SELECT run_id,step_id,attempt,role,name,uid,recipe_digest,created_at FROM workers WHERE run_id=? AND step_id=? AND attempt=? AND role=?`, runID, stepID, attempt, role))
}

func scanWorker(row interface{ Scan(...any) error }) (Worker, error) {
	var w Worker
	err := row.Scan(&w.RunID, &w.StepID, &w.Attempt, &w.Role, &w.Name, &w.UID, &w.RecipeDigest, &w.CreatedAt)
	return w, err
}

func (s *Store) Workers(ctx context.Context, runID string) ([]Worker, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT run_id,step_id,attempt,role,name,uid,recipe_digest,created_at FROM workers WHERE run_id=? ORDER BY step_id,attempt,role`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Worker{}
	for rows.Next() {
		w, err := scanWorker(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
