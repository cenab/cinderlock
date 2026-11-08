package state

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

var (
	ErrPolicyFloorMissing = errors.New("policy floor is not established for this target")
	ErrPolicyRollback     = errors.New("policy epoch is below the locally admitted floor")
	ErrPolicyConflict     = errors.New("policy digest or previous epoch conflicts with locally admitted policy")
	ErrPolicyUnadmitted   = errors.New("policy epoch is ahead of the local floor and needs explicit admission")
	ErrPolicyReplay       = errors.New("policy update was already admitted")
)

type PolicyFloor struct {
	TargetID     string `json:"targetID"`
	Epoch        int64  `json:"epoch"`
	Digest       string `json:"digest"`
	UpdateDigest string `json:"updateDigest,omitempty"`
	ObservedAt   string `json:"observedAt"`
}

func (s *Store) policyTables(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS policy_floors(target_id TEXT PRIMARY KEY,epoch INTEGER NOT NULL,digest TEXT NOT NULL,update_digest TEXT NOT NULL,observed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policy_updates(target_id TEXT NOT NULL,update_digest TEXT NOT NULL,previous_epoch INTEGER NOT NULL,previous_digest TEXT NOT NULL,epoch INTEGER NOT NULL,digest TEXT NOT NULL,admitted_at TEXT NOT NULL,PRIMARY KEY(target_id,update_digest));`)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS policy_update_evidence(target_id TEXT NOT NULL,update_digest TEXT NOT NULL,evidence_json BLOB NOT NULL,PRIMARY KEY(target_id,update_digest),FOREIGN KEY(target_id,update_digest) REFERENCES policy_updates(target_id,update_digest));`)
	return err
}

func validPolicyDigest(digest string) bool {
	if len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") || strings.ToLower(digest) != digest {
		return false
	}
	_, err := hex.DecodeString(digest[7:])
	return err == nil
}

func validPolicyFloor(target string, epoch int64, digest string) error {
	if target == "" || len(target) > 1024 || strings.ContainsAny(target, "\x00\r\n") || epoch < 1 || epoch > 9007199254740991 || !validPolicyDigest(digest) {
		return errors.New("invalid target, policy epoch or SHA256 digest")
	}
	return nil
}

func (s *Store) PolicyFloor(ctx context.Context, targetID string) (PolicyFloor, error) {
	if err := s.policyTables(ctx); err != nil {
		return PolicyFloor{}, err
	}
	var floor PolicyFloor
	err := s.db.QueryRowContext(ctx, `SELECT target_id,epoch,digest,update_digest,observed_at FROM policy_floors WHERE target_id=?`, targetID).Scan(&floor.TargetID, &floor.Epoch, &floor.Digest, &floor.UpdateDigest, &floor.ObservedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return floor, ErrPolicyFloorMissing
	}
	return floor, err
}

// CheckPolicyFloor never enrolls or advances trust. An existing target needs
// the exact admitted policy; a new target needs explicit baseline enrollment.
func (s *Store) CheckPolicyFloor(ctx context.Context, targetID string, epoch int64, digest string) error {
	if err := validPolicyFloor(targetID, epoch, digest); err != nil {
		return err
	}
	floor, err := s.PolicyFloor(ctx, targetID)
	if err != nil {
		return err
	}
	if epoch < floor.Epoch {
		return ErrPolicyRollback
	}
	if epoch > floor.Epoch {
		return ErrPolicyUnadmitted
	}
	if digest != floor.Digest {
		return ErrPolicyConflict
	}
	return nil
}

// ObservePolicyFloor explicitly enrolls a customer-approved baseline or an
// out-of-band policy. Ordinary loading must use CheckPolicyFloor instead.
func (s *Store) ObservePolicyFloor(ctx context.Context, targetID string, epoch int64, digest string) error {
	if err := validPolicyFloor(targetID, epoch, digest); err != nil {
		return err
	}
	if err := s.policyTables(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previousEpoch int64
	var previousDigest string
	err = tx.QueryRowContext(ctx, `SELECT epoch,digest FROM policy_floors WHERE target_id=?`, targetID).Scan(&previousEpoch, &previousDigest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if epoch < previousEpoch {
			return ErrPolicyRollback
		}
		if epoch == previousEpoch {
			if digest != previousDigest {
				return ErrPolicyConflict
			}
			return tx.Commit()
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_floors(target_id,epoch,digest,update_digest,observed_at) VALUES(?,?,?,'',?) ON CONFLICT(target_id) DO UPDATE SET epoch=excluded.epoch,digest=excluded.digest,update_digest='',observed_at=excluded.observed_at`, targetID, epoch, digest, now()); err != nil {
		return err
	}
	return tx.Commit()
}

// AdvancePolicyFloor is a compare-and-swap over the previously admitted policy.
// Signature and approval checks belong to the trust-update caller.
func (s *Store) AdvancePolicyFloor(ctx context.Context, targetID string, previousEpoch int64, previousDigest string, nextEpoch int64, nextDigest, updateDigest string, evidence ...json.RawMessage) error {
	if len(evidence) > 1 || len(evidence) == 1 && (!json.Valid(evidence[0]) || len(evidence[0]) > 65536) {
		return errors.New("policy admission evidence must be one bounded JSON record")
	}
	if err := validPolicyFloor(targetID, previousEpoch, previousDigest); err != nil {
		return err
	}
	if err := validPolicyFloor(targetID, nextEpoch, nextDigest); err != nil {
		return err
	}
	if nextEpoch != previousEpoch+1 || !validPolicyDigest(updateDigest) {
		return errors.New("policy update needs exactly the next epoch and an update digest")
	}
	if err := s.policyTables(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var epoch int64
	var digest string
	if err := tx.QueryRowContext(ctx, `SELECT epoch,digest FROM policy_floors WHERE target_id=?`, targetID).Scan(&epoch, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPolicyFloorMissing
		}
		return err
	}
	var replay int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_updates WHERE target_id=? AND update_digest=?`, targetID, updateDigest).Scan(&replay); err != nil {
		return err
	}
	if replay != 0 {
		return ErrPolicyReplay
	}
	if epoch != previousEpoch || digest != previousDigest {
		return ErrPolicyConflict
	}
	stamp := now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_updates(target_id,update_digest,previous_epoch,previous_digest,epoch,digest,admitted_at) VALUES(?,?,?,?,?,?,?)`, targetID, updateDigest, previousEpoch, previousDigest, nextEpoch, nextDigest, stamp); err != nil {
		return err
	}
	if len(evidence) == 1 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_update_evidence(target_id,update_digest,evidence_json) VALUES(?,?,?)`, targetID, updateDigest, []byte(evidence[0])); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_floors SET epoch=?,digest=?,update_digest=?,observed_at=? WHERE target_id=?`, nextEpoch, nextDigest, updateDigest, stamp, targetID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PolicyUpdateEvidence(ctx context.Context, targetID, updateDigest string) (json.RawMessage, error) {
	if err := s.policyTables(ctx); err != nil {
		return nil, err
	}
	var evidence []byte
	err := s.db.QueryRowContext(ctx, `SELECT evidence_json FROM policy_update_evidence WHERE target_id=? AND update_digest=?`, targetID, updateDigest).Scan(&evidence)
	return evidence, err
}
