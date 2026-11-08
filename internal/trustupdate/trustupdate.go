// Package trustupdate admits customer-controlled policy changes independently
// of vendor release signatures. Packets never supply their own trust root.
package trustupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

const Domain = "cinderlock.trust-update.v1"
const MaxPacketBytes = 1 << 20
const MaxValidity = 24 * time.Hour

type Body struct {
	spec.Header
	TargetID             string           `json:"targetID"`
	PreviousPolicyDigest string           `json:"previousPolicyDigest"`
	PreviousEpoch        int64            `json:"previousEpoch"`
	Candidate            spec.TrustPolicy `json:"candidate"`
	IssuedAt             string           `json:"issuedAt"`
	ExpiresAt            string           `json:"expiresAt"`
	DecisionReference    string           `json:"decisionReference"`
}

// Body is canonical JSON authenticated as exact bytes, not a reconstructed
// policy or a signature from keys carried inside Candidate.
type Packet struct {
	Domain    string          `json:"domain"`
	Body      json.RawMessage `json:"body"`
	Signature spec.Signature  `json:"signature"`
}

type Change struct {
	Field  string          `json:"field"`
	Before json.RawMessage `json:"before"`
	After  json.RawMessage `json:"after"`
}

type Preview struct {
	spec.Header
	TargetID             string           `json:"targetID"`
	PacketDigest         string           `json:"packetDigest"`
	PreviousPolicyDigest string           `json:"previousPolicyDigest"`
	PreviousEpoch        int64            `json:"previousEpoch"`
	CandidateDigest      string           `json:"candidateDigest"`
	Candidate            spec.TrustPolicy `json:"candidate"`
	SignerKeyID          string           `json:"signerKeyID"`
	IssuedAt             string           `json:"issuedAt"`
	ExpiresAt            string           `json:"expiresAt"`
	DecisionReference    string           `json:"decisionReference"`
	Changes              []Change         `json:"changes"`
}

func Sign(body Body, keyID string, key ed25519.PrivateKey) (Packet, error) {
	if err := validateBody(body); err != nil {
		return Packet{}, err
	}
	if keyID == "" || len(key) != ed25519.PrivateKeySize {
		return Packet{}, spec.Err(16, "policy update signing needs an Ed25519 key and key ID")
	}
	data, err := spec.Canonical(body)
	if err != nil {
		return Packet{}, err
	}
	if len(data) > MaxPacketBytes {
		return Packet{}, spec.Err(2, "trust update body exceeds 1 MiB limit")
	}
	signature := ed25519.Sign(key, append([]byte(Domain+"\x00"), data...))
	return Packet{Domain: Domain, Body: data, Signature: spec.Signature{KeyID: keyID, Algorithm: "Ed25519", Signature: base64.StdEncoding.EncodeToString(signature)}}, nil
}

func Verify(packet Packet, current spec.TrustPolicy, targetID string, now time.Time) (Preview, error) {
	if packet.Domain != Domain || len(packet.Body) == 0 || len(packet.Body) > MaxPacketBytes || packet.Signature.Algorithm != "Ed25519" {
		return Preview{}, spec.Err(16, "unsupported trust-update domain, algorithm or size")
	}
	if err := validatePolicyAt(current, now); err != nil {
		return Preview{}, err
	}
	canonical, err := spec.CanonicalRaw(packet.Body)
	if err != nil || !bytes.Equal(canonical, packet.Body) {
		return Preview{}, spec.Err(12, "trust-update body must be exact canonical JSON")
	}
	var signer *spec.TrustedKey
	for _, key := range current.Spec.Keys {
		if key.ID == packet.Signature.KeyID && policyAdmin(current, key) {
			copy := key
			signer = &copy
			break
		}
	}
	if signer == nil {
		return Preview{}, spec.Err(16, "signer is not a current nonrevoked global policy administrator")
	}
	public, err := base64.StdEncoding.DecodeString(signer.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return Preview{}, spec.Err(16, "policy administrator public key is invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(packet.Signature.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(public), append([]byte(Domain+"\x00"), packet.Body...), signature) {
		return Preview{}, spec.Err(16, "trust-update signature is not authorized by the current policy")
	}
	var body Body
	if err := spec.Decode(packet.Body, &body); err != nil {
		return Preview{}, err
	}
	if err := validateBody(body); err != nil {
		return Preview{}, err
	}
	currentDigest, err := spec.Digest(current)
	if err != nil {
		return Preview{}, err
	}
	if body.TargetID != targetID || body.PreviousPolicyDigest != currentDigest || body.PreviousEpoch != current.Spec.Epoch || body.Candidate.Spec.Epoch != current.Spec.Epoch+1 || body.Metadata.Name != current.Metadata.Name || body.Candidate.Metadata.Name != current.Metadata.Name || current.Metadata.Name == "" {
		return Preview{}, spec.Err(16, "trust update differs from the current target, policy identity, digest or next epoch")
	}
	issued, _ := time.Parse(time.RFC3339Nano, body.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, body.ExpiresAt)
	if now.Before(issued) || !now.Before(expires) {
		return Preview{}, spec.Err(16, "trust update is not yet valid or has expired")
	}
	if current.Spec.ExpiresAt != "" {
		currentExpiry, _ := time.Parse(time.RFC3339Nano, current.Spec.ExpiresAt)
		if expires.After(currentExpiry) {
			return Preview{}, spec.Err(16, "trust update outlives current policy authority")
		}
	}
	if err := validatePolicyAt(body.Candidate, now); err != nil {
		return Preview{}, err
	}
	if err := validateTransition(current, body.Candidate, *signer); err != nil {
		return Preview{}, err
	}
	candidateDigest, err := spec.Digest(body.Candidate)
	if err != nil {
		return Preview{}, err
	}
	packetDigest, err := spec.Digest(packet)
	if err != nil {
		return Preview{}, err
	}
	changes, err := policyChanges(current, body.Candidate)
	if err != nil {
		return Preview{}, err
	}
	preview := Preview{Header: spec.NewHeader("TrustUpdatePreview"), TargetID: targetID, PacketDigest: packetDigest, PreviousPolicyDigest: currentDigest, PreviousEpoch: current.Spec.Epoch, CandidateDigest: candidateDigest, Candidate: body.Candidate, SignerKeyID: signer.ID, IssuedAt: body.IssuedAt, ExpiresAt: body.ExpiresAt, DecisionReference: body.DecisionReference, Changes: changes}
	preview.Metadata.Name = current.Metadata.Name
	return preview, nil
}

func validateBody(body Body) error {
	if err := spec.ValidateHeader(body.Header, "TrustUpdate"); err != nil {
		return err
	}
	if body.TargetID == "" || len(body.TargetID) > 1024 || strings.ContainsAny(body.TargetID, "\x00\r\n") || body.PreviousEpoch < 1 || body.PreviousEpoch >= 9007199254740991 || body.Candidate.Spec.Epoch != body.PreviousEpoch+1 || body.DecisionReference == "" || len(body.DecisionReference) > 4096 || strings.ContainsAny(body.DecisionReference, "\x00\r\n") {
		return spec.Err(2, "trust update needs a target, exact next epoch and bounded decision reference")
	}
	if len(body.PreviousPolicyDigest) != 71 || !strings.HasPrefix(body.PreviousPolicyDigest, "sha256:") || strings.ToLower(body.PreviousPolicyDigest) != body.PreviousPolicyDigest {
		return spec.Err(2, "trust update needs previous policy SHA256 digest")
	}
	if _, err := hex.DecodeString(body.PreviousPolicyDigest[7:]); err != nil {
		return spec.Err(2, "invalid previous policy SHA256 digest")
	}
	issued, err := time.Parse(time.RFC3339Nano, body.IssuedAt)
	if err != nil {
		return spec.Err(2, "invalid trust-update issuance time")
	}
	expires, err := time.Parse(time.RFC3339Nano, body.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > MaxValidity {
		return spec.Err(2, "trust update validity must be positive and at most 24 hours")
	}
	return nil
}

func validatePolicyAt(policy spec.TrustPolicy, now time.Time) error {
	copy := policy
	copy.Spec.ExpiresAt = ""
	if err := spec.ValidatePolicy(copy); err != nil {
		return err
	}
	if policy.Spec.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339Nano, policy.Spec.ExpiresAt)
		if err != nil || !now.Before(expires) {
			return spec.Err(16, "trust policy has expired or has an invalid validity time")
		}
	}
	return nil
}

func policyAdmin(policy spec.TrustPolicy, key spec.TrustedKey) bool {
	if key.Revoked || !slices.Contains(key.Roles, "policy") || !slices.Contains(key.Applications, "*") || !slices.Contains(key.Channels, "*") {
		return false
	}
	for _, other := range policy.Spec.Keys {
		if samePublicKey(other.PublicKey, key.PublicKey) && slices.Contains(other.Roles, "release") {
			return false
		}
	}
	return true
}

func validateTransition(current, candidate spec.TrustPolicy, signer spec.TrustedKey) error {
	retainedSigner := false
	for _, key := range candidate.Spec.Keys {
		for _, old := range current.Spec.Keys {
			if key.ID == old.ID && !samePublicKey(key.PublicKey, old.PublicKey) {
				return spec.Err(16, "key material cannot change under an existing key ID")
			}
			if slices.Contains(key.Roles, "policy") && slices.Contains(old.Roles, "release") && samePublicKey(key.PublicKey, old.PublicKey) {
				return spec.Err(16, "known release signing material cannot be promoted into policy administration")
			}
		}
		if key.ID == signer.ID && samePublicKey(key.PublicKey, signer.PublicKey) && policyAdmin(candidate, key) {
			retainedSigner = true
		}
	}
	if !retainedSigner {
		return spec.Err(16, "update signer must remain an unchanged nonrevoked global policy administrator; rotate with an overlap epoch")
	}
	for channel, minimum := range current.Spec.MinSequence {
		if candidate.Spec.MinSequence[channel] < minimum {
			return spec.Err(16, "policy update cannot lower or remove an existing release sequence minimum")
		}
	}
	for _, minimum := range candidate.Spec.MinSequence {
		if minimum < 0 {
			return spec.Err(16, "policy release sequence minima cannot be negative")
		}
	}
	return nil
}

func samePublicKey(first, second string) bool {
	a, firstErr := base64.StdEncoding.DecodeString(first)
	b, secondErr := base64.StdEncoding.DecodeString(second)
	return firstErr == nil && secondErr == nil && bytes.Equal(a, b)
}

func policyChanges(current, candidate spec.TrustPolicy) ([]Change, error) {
	changes := []Change{}
	before, err := spec.Canonical(current.Spec)
	if err != nil {
		return nil, err
	}
	after, err := spec.Canonical(candidate.Spec)
	if err != nil {
		return nil, err
	}
	var oldFields, newFields map[string]json.RawMessage
	if err := json.Unmarshal(before, &oldFields); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(after, &newFields); err != nil {
		return nil, err
	}
	keys := []string{}
	for key := range oldFields {
		keys = append(keys, key)
	}
	for key := range newFields {
		if _, ok := oldFields[key]; !ok {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	for _, key := range keys {
		old := oldFields[key]
		new := newFields[key]
		if bytes.Equal(old, new) {
			continue
		}
		if old == nil {
			old = json.RawMessage("null")
		}
		if new == nil {
			new = json.RawMessage("null")
		}
		changes = append(changes, Change{Field: key, Before: old, After: new})
	}
	return changes, nil
}
