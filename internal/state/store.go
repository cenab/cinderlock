package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	_ "modernc.org/sqlite"
)

var ErrActiveRun = errors.New("application has an unresolved active run")
var ErrAuthorizationUsed = errors.New("authorization already belongs to another run")

type Store struct{ db *sql.DB }

type Run struct {
	ID           string          `json:"id"`
	Application  string          `json:"application"`
	Namespace    string          `json:"namespace"`
	TargetID     string          `json:"targetID"`
	PlanDigest   string          `json:"planDigest"`
	BundleDigest string          `json:"bundleDigest"`
	State        string          `json:"state"`
	Active       bool            `json:"active"`
	Plan         json.RawMessage `json:"plan"`
	Site         json.RawMessage `json:"site"`
	Result       json.RawMessage `json:"result,omitempty"`
	CreatedAt    string          `json:"createdAt"`
	UpdatedAt    string          `json:"updatedAt"`
}

type Operation struct {
	RunID      string          `json:"runID"`
	StepID     string          `json:"stepID"`
	Attempt    int             `json:"attempt"`
	State      string          `json:"state"`
	Intent     json.RawMessage `json:"intent"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
	ExternalID string          `json:"externalID,omitempty"`
	UpdatedAt  string          `json:"updatedAt"`
}

type Event struct {
	RunID string          `json:"runID"`
	Seq   int64           `json:"seq"`
	Type  string          `json:"type"`
	Data  json.RawMessage `json:"data"`
	Time  string          `json:"time"`
}

// Authorization binds a nonce to the run admitted in the same transaction.
type Authorization struct {
	Nonce        string
	PolicyDigest string
	ExpiresAt    string
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("state database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("state database must be a private regular file")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.init(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) init(ctx context.Context) error {
	for _, pragma := range []string{"PRAGMA foreign_keys=ON", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=5000"} {
		if _, err := s.db.ExecContext(ctx, pragma); err != nil {
			return err
		}
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > 2 {
		return errors.New("state database was created by a newer incompatible Cinderlock version")
	}
	if version > 0 {
		_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS checkpoints(run_id TEXT PRIMARY KEY REFERENCES runs(id), digest TEXT NOT NULL, snapshot_json BLOB NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workers(run_id TEXT NOT NULL,step_id TEXT NOT NULL,attempt INTEGER NOT NULL,role TEXT NOT NULL,name TEXT NOT NULL,uid TEXT NOT NULL,recipe_digest TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(run_id,step_id,attempt,role),FOREIGN KEY(run_id,step_id,attempt) REFERENCES operations(run_id,step_id,attempt));
CREATE TABLE IF NOT EXISTS run_protocols(run_id TEXT PRIMARY KEY REFERENCES runs(id),worker_protocol TEXT NOT NULL);
PRAGMA user_version=2;`)
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
CREATE TABLE runs(id TEXT PRIMARY KEY, application TEXT NOT NULL, namespace TEXT NOT NULL, target_id TEXT NOT NULL,
plan_digest TEXT NOT NULL, bundle_digest TEXT NOT NULL, state TEXT NOT NULL, active INTEGER NOT NULL,
plan_json BLOB NOT NULL, site_json BLOB NOT NULL, result_json BLOB, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX one_active_run ON runs(application,namespace,target_id) WHERE active=1;
CREATE TABLE operations(run_id TEXT NOT NULL REFERENCES runs(id), step_id TEXT NOT NULL, attempt INTEGER NOT NULL,
state TEXT NOT NULL, intent_json BLOB NOT NULL, evidence_json BLOB, external_id TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
PRIMARY KEY(run_id,step_id,attempt));
CREATE TABLE events(run_id TEXT NOT NULL REFERENCES runs(id), seq INTEGER NOT NULL, type TEXT NOT NULL, data_json BLOB NOT NULL, time TEXT NOT NULL, PRIMARY KEY(run_id,seq));
CREATE TABLE authorizations(nonce TEXT PRIMARY KEY, plan_digest TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES runs(id), policy_digest TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE release_floors(target_id TEXT NOT NULL, application TEXT NOT NULL, channel TEXT NOT NULL, sequence INTEGER NOT NULL, bundle_digest TEXT NOT NULL, PRIMARY KEY(target_id,application,channel));
CREATE TABLE checkpoints(run_id TEXT PRIMARY KEY REFERENCES runs(id), digest TEXT NOT NULL, snapshot_json BLOB NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE workers(run_id TEXT NOT NULL,step_id TEXT NOT NULL,attempt INTEGER NOT NULL,role TEXT NOT NULL,name TEXT NOT NULL,uid TEXT NOT NULL,recipe_digest TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(run_id,step_id,attempt,role),FOREIGN KEY(run_id,step_id,attempt) REFERENCES operations(run_id,step_id,attempt));
CREATE TABLE run_protocols(run_id TEXT PRIMARY KEY REFERENCES runs(id),worker_protocol TEXT NOT NULL);
PRAGMA user_version=2;`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Checkpoint(ctx context.Context, id string) (string, json.RawMessage, error) {
	var digest string
	var body []byte
	err := s.db.QueryRowContext(ctx, `SELECT digest,snapshot_json FROM checkpoints WHERE run_id=?`, id).Scan(&digest, &body)
	return digest, body, err
}
func (s *Store) SetCheckpoint(ctx context.Context, id, digest string, snapshot any) error {
	body, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO checkpoints(run_id,digest,snapshot_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET digest=excluded.digest,snapshot_json=excluded.snapshot_json,updated_at=excluded.updated_at`, id, digest, body, now())
	if err != nil {
		return err
	}
	if err := appendEvent(ctx, tx, id, "checkpoint", map[string]string{"digest": digest}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Close() error { return s.db.Close() }

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (s *Store) CreateRun(ctx context.Context, r Run) error {
	return s.AdmitRun(ctx, r, "", nil)
}

// AdmitRun atomically creates the run, consumes its approval and, for recovery,
// transfers the unresolved local gate. A rejected nonce leaves neither a new
// run nor a partially transferred recovery gate behind.
func (s *Store) AdmitRun(ctx context.Context, r Run, sourceID string, approval *Authorization) error {
	if r.ID == "" || r.Application == "" || r.TargetID == "" || r.PlanDigest == "" || !json.Valid(r.Plan) || !json.Valid(r.Site) {
		return errors.New("incomplete run identity or invalid plan/site JSON")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if sourceID != "" {
		var active bool
		var target, app, namespace string
		if err := tx.QueryRowContext(ctx, `SELECT active,target_id,application,namespace FROM runs WHERE id=?`, sourceID).Scan(&active, &target, &app, &namespace); err != nil {
			return err
		}
		if !active || target != r.TargetID || app != r.Application || namespace != r.Namespace {
			return errors.New("recovery source is not the unresolved run for this application target namespace")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE runs SET active=0,updated_at=? WHERE id=?`, now(), sourceID); err != nil {
			return err
		}
	}
	stamp := now()
	_, err = tx.ExecContext(ctx, `INSERT INTO runs(id,application,namespace,target_id,plan_digest,bundle_digest,state,active,plan_json,site_json,result_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.ID, r.Application, r.Namespace, r.TargetID, r.PlanDigest, r.BundleDigest, r.State, true, []byte(r.Plan), []byte(r.Site), nil, stamp, stamp)
	if err != nil {
		var existing string
		if qerr := tx.QueryRowContext(ctx, `SELECT id FROM runs WHERE application=? AND namespace=? AND target_id=? AND active=1`, r.Application, r.Namespace, r.TargetID).Scan(&existing); qerr == nil {
			return fmt.Errorf("%w: %s", ErrActiveRun, existing)
		}
		return err
	}
	if approval != nil {
		if err := consumeAuthorization(ctx, tx, approval.Nonce, r.PlanDigest, r.ID, approval.PolicyDigest, approval.ExpiresAt); err != nil {
			return err
		}
		if err := appendEvent(ctx, tx, r.ID, "authorization_bound", map[string]string{"policyDigest": approval.PolicyDigest, "expiresAt": approval.ExpiresAt}); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO run_protocols(run_id,worker_protocol) VALUES(?,?)`, r.ID, "server-uid-v1"); err != nil {
		return err
	}
	if err := appendEvent(ctx, tx, r.ID, "run_created", map[string]string{"state": r.State, "planDigest": r.PlanDigest, "bundleDigest": r.BundleDigest}); err != nil {
		return err
	}
	if sourceID != "" {
		if err := appendEvent(ctx, tx, sourceID, "run_superseded", map[string]string{"recoveryRun": r.ID}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Successor reads the single gate transfer committed by AdmitRun.
func (s *Store) Successor(ctx context.Context, sourceID string) (string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data_json FROM events WHERE run_id=? AND type='run_superseded' ORDER BY seq DESC LIMIT 2`, sourceID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	successor := ""
	for rows.Next() {
		var body []byte
		var edge struct {
			RunID string `json:"recoveryRun"`
		}
		if err := rows.Scan(&body); err != nil {
			return "", err
		}
		if err := json.Unmarshal(body, &edge); err != nil {
			return "", err
		}
		if successor != "" || edge.RunID == "" {
			return "", errors.New("ambiguous recorded run successor")
		}
		successor = edge.RunID
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if successor == "" {
		return "", errors.New("recorded run successor is unavailable")
	}
	return successor, nil
}

// Supersede transfers the unresolved local gate only when a reviewed recovery run is created atomically.
func (s *Store) Supersede(ctx context.Context, sourceID string, r Run) error {
	return s.AdmitRun(ctx, r, sourceID, nil)
}

func scanRun(row interface{ Scan(...any) error }) (Run, error) {
	var r Run
	var result []byte
	err := row.Scan(&r.ID, &r.Application, &r.Namespace, &r.TargetID, &r.PlanDigest, &r.BundleDigest, &r.State, &r.Active, &r.Plan, &r.Site, &result, &r.CreatedAt, &r.UpdatedAt)
	r.Result = result
	return r, err
}

const runFields = "id,application,namespace,target_id,plan_digest,bundle_digest,state,active,plan_json,site_json,result_json,created_at,updated_at"

func (s *Store) Run(ctx context.Context, id string) (Run, error) {
	return scanRun(s.db.QueryRowContext(ctx, "SELECT "+runFields+" FROM runs WHERE id=?", id))
}

// ActiveRun uses the same exact scope as the unique mutation gate.
func (s *Store) ActiveRun(ctx context.Context, application, namespace, targetID string) (Run, error) {
	return scanRun(s.db.QueryRowContext(ctx, "SELECT "+runFields+" FROM runs WHERE application=? AND namespace=? AND target_id=? AND active=1", application, namespace, targetID))
}

func (s *Store) Runs(ctx context.Context) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+runFields+" FROM runs ORDER BY created_at DESC,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SetState(ctx context.Context, id, status string, active bool, result any) error {
	var body []byte
	var err error
	if result != nil {
		body, err = json.Marshal(result)
		if err != nil {
			return err
		}
		if len(body) > spec.MaxDocumentBytes {
			return errors.New("run result exceeds document size limit")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `UPDATE runs SET state=?,active=?,result_json=COALESCE(?,result_json),updated_at=? WHERE id=?`, status, active, body, now(), id)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	if err := appendEvent(ctx, tx, id, "run_state", map[string]any{"state": status, "active": active}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Intent(ctx context.Context, runID, stepID string, intent any, externalID string) (Operation, error) {
	body, err := json.Marshal(intent)
	if err != nil {
		return Operation{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, err
	}
	defer tx.Rollback()
	var attempt int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(attempt),0)+1 FROM operations WHERE run_id=? AND step_id=?`, runID, stepID).Scan(&attempt); err != nil {
		return Operation{}, err
	}
	o := Operation{RunID: runID, StepID: stepID, Attempt: attempt, State: "intent", Intent: body, ExternalID: externalID, UpdatedAt: now()}
	_, err = tx.ExecContext(ctx, `INSERT INTO operations(run_id,step_id,attempt,state,intent_json,external_id,updated_at) VALUES(?,?,?,?,?,?,?)`, runID, stepID, attempt, o.State, body, externalID, o.UpdatedAt)
	if err != nil {
		return Operation{}, err
	}
	if err := appendEvent(ctx, tx, runID, "operation_intent", map[string]any{"stepID": stepID, "attempt": attempt, "externalID": externalID}); err != nil {
		return Operation{}, err
	}
	return o, tx.Commit()
}

func (s *Store) Complete(ctx context.Context, o Operation, status string, evidence any) error {
	if status != "complete" && status != "failed" && status != "uncertain" {
		return errors.New("invalid operation outcome")
	}
	body, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `UPDATE operations SET state=?,evidence_json=?,updated_at=? WHERE run_id=? AND step_id=? AND attempt=? AND state IN ('intent','uncertain')`, status, body, now(), o.RunID, o.StepID, o.Attempt)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("operation intent missing or already finalized")
	}
	if err := appendEvent(ctx, tx, o.RunID, "operation_outcome", map[string]any{"stepID": o.StepID, "attempt": o.Attempt, "state": status, "externalID": o.ExternalID}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Operations(ctx context.Context, id string) ([]Operation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT run_id,step_id,attempt,state,intent_json,evidence_json,external_id,updated_at FROM operations WHERE run_id=? ORDER BY step_id,attempt`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Operation{}
	for rows.Next() {
		var o Operation
		var ev []byte
		if err := rows.Scan(&o.RunID, &o.StepID, &o.Attempt, &o.State, &o.Intent, &ev, &o.ExternalID, &o.UpdatedAt); err != nil {
			return nil, err
		}
		o.Evidence = ev
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) Event(ctx context.Context, id, kind string, value any) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := appendEvent(ctx, tx, id, kind, value); err != nil {
		return err
	}
	return tx.Commit()
}

func appendEvent(ctx context.Context, tx *sql.Tx, id, kind string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events(run_id,seq,type,data_json,time) SELECT ?,COALESCE(MAX(seq),0)+1,?,?,? FROM events WHERE run_id=?`, id, kind, body, now(), id)
	return err
}

func (s *Store) Events(ctx context.Context, id string) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT run_id,seq,type,data_json,time FROM events WHERE run_id=? ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.RunID, &e.Seq, &e.Type, &e.Data, &e.Time); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ConsumeAuthorization(ctx context.Context, nonce, planDigest, runID, policyDigest, expiresAt string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := consumeAuthorization(ctx, tx, nonce, planDigest, runID, policyDigest, expiresAt); err != nil {
		return err
	}
	return tx.Commit()
}

func consumeAuthorization(ctx context.Context, tx *sql.Tx, nonce, planDigest, runID, policyDigest, expiresAt string) error {
	if nonce == "" || planDigest == "" || runID == "" || policyDigest == "" {
		return errors.New("incomplete authorization binding")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO authorizations(nonce,plan_digest,run_id,policy_digest,expires_at) VALUES(?,?,?,?,?) ON CONFLICT(nonce) DO NOTHING`, nonce, planDigest, runID, policyDigest, expiresAt)
	if err != nil {
		return err
	}
	var p, r, policy, expiry string
	if err := tx.QueryRowContext(ctx, `SELECT plan_digest,run_id,policy_digest,expires_at FROM authorizations WHERE nonce=?`, nonce).Scan(&p, &r, &policy, &expiry); err != nil {
		return err
	}
	if p != planDigest || r != runID || policy != policyDigest || expiry != expiresAt {
		return ErrAuthorizationUsed
	}
	return nil
}

func (s *Store) ReleaseFloor(ctx context.Context, target, app, channel string) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT sequence FROM release_floors WHERE target_id=? AND application=? AND channel=?`, target, app, channel).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

func (s *Store) AcceptRelease(ctx context.Context, target, app, channel string, sequence int64, digest string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO release_floors(target_id,application,channel,sequence,bundle_digest) VALUES(?,?,?,?,?) ON CONFLICT(target_id,application,channel) DO UPDATE SET sequence=excluded.sequence,bundle_digest=excluded.bundle_digest WHERE excluded.sequence>release_floors.sequence`, target, app, channel, sequence, digest)
	return err
}
