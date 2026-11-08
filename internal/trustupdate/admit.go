package trustupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	"golang.org/x/sys/unix"
)

type Receipt struct {
	spec.Header
	TargetID             string `json:"targetID"`
	PacketDigest         string `json:"packetDigest"`
	PreviousPolicyDigest string `json:"previousPolicyDigest"`
	CandidateDigest      string `json:"candidateDigest"`
	Epoch                int64  `json:"epoch"`
	SignerKeyID          string `json:"signerKeyID"`
	DecisionReference    string `json:"decisionReference"`
	OutputPath           string `json:"outputPath"`
	State                string `json:"state"`
	CandidatePrepared    bool   `json:"candidatePrepared"`
	Admitted             bool   `json:"admitted"`
	AdmittedAt           string `json:"admittedAt,omitempty"`
	ClockSource          string `json:"clockSource"`
}

// Read accepts the canonical JSON packet format only. At most one trailing LF
// is a file delimiter and is not part of the canonical packet identity.
func Read(path string) (Packet, error) {
	data, _, err := readRegular(path, MaxPacketBytes)
	if err != nil {
		return Packet{}, err
	}
	data = bytes.TrimSuffix(data, []byte{'\n'})
	canonical, err := spec.CanonicalRaw(data)
	if err != nil || !bytes.Equal(data, canonical) {
		return Packet{}, spec.Err(12, "trust-update packet must be canonical JSON")
	}
	var packet Packet
	if err := spec.Decode(data, &packet); err != nil {
		return Packet{}, err
	}
	return packet, nil
}

func Write(path string, packet Packet) error {
	data, err := spec.Canonical(packet)
	if err != nil {
		return err
	}
	if len(data) > MaxPacketBytes {
		return spec.Err(2, "trust-update packet exceeds 1 MiB limit")
	}
	return writeNew(path, append(data, '\n'))
}

// Admit re-verifies current authority and the reviewed packet, prepares a new
// durable file, and compare-and-swaps the local floor. It never overwrites the
// active policy or edits Site. File publication and SQLite are separate commit
// domains: an error after preparation returns its path without claiming admission.
func Admit(ctx context.Context, packet Packet, currentPolicyPath, targetID, approvedPacketDigest, outputPath string, store *state.Store, now time.Time) (Receipt, error) {
	started := time.Now()
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if store == nil {
		return Receipt{}, spec.Err(16, "policy update admission requires a durable local floor")
	}
	currentData, currentIdentity, err := readRegular(currentPolicyPath, spec.MaxDocumentBytes)
	if err != nil {
		return Receipt{}, err
	}
	var current spec.TrustPolicy
	if err := spec.Decode(currentData, &current); err != nil {
		return Receipt{}, err
	}
	preview, err := Verify(packet, current, targetID, now)
	if err != nil {
		return Receipt{}, err
	}
	if approvedPacketDigest == "" || approvedPacketDigest != preview.PacketDigest {
		return Receipt{}, spec.Err(16, "exact reviewed trust-update packet digest is required")
	}
	if err := store.CheckPolicyFloor(ctx, targetID, preview.PreviousEpoch, preview.PreviousPolicyDigest); err != nil {
		return Receipt{}, spec.Err(16, "current policy is not the independently enrolled target floor: %v", err)
	}
	floor, err := store.PolicyFloor(ctx, targetID)
	if err != nil {
		return Receipt{}, err
	}
	observed, err := time.Parse(time.RFC3339Nano, floor.ObservedAt)
	if err != nil || now.Before(observed.Add(-time.Minute)) {
		return Receipt{}, spec.Err(16, "local clock is behind admitted policy history; reconcile the clock before updating trust")
	}
	active, err := filepath.Abs(currentPolicyPath)
	if err != nil {
		return Receipt{}, err
	}
	output, err := filepath.Abs(outputPath)
	if err != nil {
		return Receipt{}, err
	}
	if outputPath == "" || output == active {
		return Receipt{}, spec.Err(16, "trust update requires a new policy path and cannot replace the active policy")
	}
	candidate, err := spec.Canonical(preview.Candidate)
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{Header: spec.NewHeader("TrustUpdateReceipt"), TargetID: targetID, PacketDigest: preview.PacketDigest, PreviousPolicyDigest: preview.PreviousPolicyDigest, CandidateDigest: preview.CandidateDigest, Epoch: preview.Candidate.Spec.Epoch, SignerKeyID: preview.SignerKeyID, DecisionReference: preview.DecisionReference, OutputPath: output, State: "preparing", ClockSource: "local wall clock"}
	receipt.Metadata.Name = current.Metadata.Name
	if err := writeNew(output, append(candidate, '\n')); err != nil {
		return receipt, err
	}
	receipt.CandidatePrepared = true
	receipt.State = "prepared"
	latest, identity, err := readRegular(currentPolicyPath, spec.MaxDocumentBytes)
	if err != nil {
		return receipt, spec.Err(13, "candidate file was prepared but current policy cannot be revalidated; admission was not confirmed")
	}
	var reread spec.TrustPolicy
	if err := spec.Decode(latest, &reread); err != nil {
		return receipt, spec.Err(13, "candidate file was prepared but current policy changed; admission was not confirmed")
	}
	digest, err := spec.Digest(reread)
	if err != nil || digest != preview.PreviousPolicyDigest || !os.SameFile(currentIdentity, identity) {
		return receipt, spec.Err(13, "candidate file was prepared but current policy identity changed; admission was not confirmed")
	}
	decisionTime := now.Add(time.Since(started))
	if _, err := Verify(packet, reread, targetID, decisionTime); err != nil {
		return receipt, spec.Err(13, "candidate file was prepared but current update authority expired or changed before admission")
	}
	admitted := receipt
	admitted.Admitted = true
	admitted.State = "admitted"
	admitted.AdmittedAt = decisionTime.UTC().Format(time.RFC3339Nano)
	evidence, err := spec.Canonical(admitted)
	if err != nil {
		return receipt, err
	}
	if err := store.AdvancePolicyFloor(ctx, targetID, preview.PreviousEpoch, preview.PreviousPolicyDigest, preview.Candidate.Spec.Epoch, preview.CandidateDigest, preview.PacketDigest, json.RawMessage(evidence)); err != nil {
		receipt.State = "needs_reconciliation"
		return receipt, spec.Err(13, "candidate file was prepared but policy floor admission was not confirmed: %v", err)
	}
	return admitted, nil
}

func readRegular(path string, limit int64) ([]byte, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	identity, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !identity.Mode().IsRegular() || identity.Size() > limit {
		return nil, nil, spec.Err(2, "policy input must be a bounded non-symlink regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, spec.Err(2, "policy input exceeds size limit")
	}
	return data, identity, nil
}

func writeNew(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	if err := directory.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}
