package catalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

const externalEvidenceDomain = "cinderlock.external-evidence.v1\x00"

type EvidenceProducer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type EvidenceCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// ExternalEvidence preserves the producer's claim and limitations. It cannot
// confer execution authority or replace the engine's own acceptance checks.
type ExternalEvidence struct {
	APIVersion     string           `json:"apiVersion"`
	Kind           string           `json:"kind"`
	SchemaVersion  int              `json:"schemaVersion"`
	Project        string           `json:"project"`
	Site           string           `json:"site"`
	Producer       EvidenceProducer `json:"producer"`
	Subject        EvidenceSubject  `json:"subject"`
	ObservedAt     string           `json:"observedAt"`
	ExpiresAt      string           `json:"expiresAt"`
	Scope          string           `json:"scope"`
	ClaimedResult  string           `json:"claimedResult"`
	Checks         []EvidenceCheck  `json:"checks"`
	Findings       []spec.Finding   `json:"findings"`
	Coverage       []string         `json:"coverage"`
	Limitations    []string         `json:"limitations"`
	RuntimeCapture *RuntimeCapture  `json:"runtimeCapture,omitempty"`
}
type SignedExternalEvidence struct {
	Body      json.RawMessage `json:"body"`
	KeyID     string          `json:"keyID"`
	Signature string          `json:"signature"`
}
type EvidenceKey struct {
	ID           string   `json:"id"`
	PublicKey    string   `json:"publicKey"`
	Producer     string   `json:"producer"`
	Versions     []string `json:"versions"`
	Projects     []string `json:"projects"`
	Sites        []string `json:"sites"`
	Applications []string `json:"applications"`
	Profiles     []string `json:"profiles"`
	Scopes       []string `json:"scopes"`
	NotAfter     string   `json:"notAfter,omitempty"`
	Revoked      bool     `json:"revoked,omitempty"`
}
type EvidenceExpectation struct {
	Project string          `json:"project"`
	Site    string          `json:"site"`
	Subject EvidenceSubject `json:"subject"`
	Scope   string          `json:"scope"`
}
type VerifiedExternalEvidence struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Digest     string           `json:"digest"`
	Integrity  string           `json:"integrity"`
	Acceptance string           `json:"acceptance"`
	Evidence   ExternalEvidence `json:"evidence"`
	Notice     string           `json:"notice"`
}
type externalEvidenceRecord struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	RunDigest  string                 `json:"runDigest"`
	Signed     SignedExternalEvidence `json:"signed"`
	VerifiedAt string                 `json:"verifiedAt"`
}

func evidenceScope(scope string) bool {
	return contains([]string{"network-isolation", "security-scan", "model-evaluation", "backup-restore"}, scope)
}
func evidenceStatus(status string) bool {
	return contains([]string{"pass", "fail", "blocked", "not_tested"}, status)
}

func validateEvidence(body ExternalEvidence) error {
	if body.APIVersion != spec.APIVersion || body.Kind != "ExternalEvidence" || body.SchemaVersion != 1 {
		return errors.New("unsupported typed external evidence")
	}
	if !identifier.MatchString(body.Project) || !identifier.MatchString(body.Site) || !identifier.MatchString(body.Producer.Name) || body.Producer.Version == "" || len(body.Producer.Version) > 128 {
		return errors.New("external evidence requires producer version and explicit project/site")
	}
	subject := body.Subject
	if subject.RunID == "" || subject.Application == "" || subject.TargetID == "" || subject.Profile == "" || !spec.ValidDigest(subject.PlanDigest) || !spec.ValidDigest(subject.BundleDigest) || !spec.ValidDigest(subject.TestScopeDigest) {
		return errors.New("external evidence requires exact run, plan, application, bundle, target, profile, and test scope")
	}
	observed, err := time.Parse(time.RFC3339Nano, body.ObservedAt)
	if err != nil {
		return errors.New("invalid evidence observation time")
	}
	expires, err := time.Parse(time.RFC3339Nano, body.ExpiresAt)
	if err != nil || !expires.After(observed) {
		return errors.New("invalid evidence scope expiry")
	}
	if !evidenceScope(body.Scope) || !evidenceStatus(body.ClaimedResult) || len(body.Checks) == 0 || len(body.Checks) > 128 || len(body.Findings) > 128 || len(body.Coverage) == 0 || len(body.Coverage) > 128 || len(body.Limitations) > 128 {
		return errors.New("external evidence scope, result, checks, and coverage must be explicit and bounded")
	}
	seen := map[string]bool{}
	for _, c := range body.Checks {
		if !identifier.MatchString(c.ID) || seen[c.ID] || !evidenceStatus(c.Status) {
			return errors.New("invalid or duplicate external evidence check")
		}
		seen[c.ID] = true
	}
	if body.RuntimeCapture != nil {
		return validateRuntimeCapture(*body.RuntimeCapture, body.Scope, observed)
	}
	return nil
}

func validateEvidenceKeys(keys []EvidenceKey) error {
	seen := map[string]bool{}
	for _, key := range keys {
		raw, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize || !identifier.MatchString(key.ID) || seen[key.ID] || !identifier.MatchString(key.Producer) || len(key.Versions) == 0 || len(key.Projects) == 0 || len(key.Sites) == 0 || len(key.Applications) == 0 || len(key.Profiles) == 0 || len(key.Scopes) == 0 {
			return errors.New("evidence key requires valid unique identity and explicit producer/version/project/site/application/profile/scope admission")
		}
		seen[key.ID] = true
		for _, scope := range key.Scopes {
			if !evidenceScope(scope) {
				return errors.New("unsupported external evidence key scope")
			}
		}
		if key.NotAfter != "" {
			if _, err = time.Parse(time.RFC3339Nano, key.NotAfter); err != nil {
				return errors.New("invalid evidence key expiry")
			}
		}
	}
	return nil
}

func SignExternalEvidence(body ExternalEvidence, keyID string, key ed25519.PrivateKey) (SignedExternalEvidence, error) {
	if len(key) != ed25519.PrivateKeySize || !identifier.MatchString(keyID) {
		return SignedExternalEvidence{}, errors.New("invalid external evidence signing key")
	}
	body.APIVersion = spec.APIVersion
	body.Kind = "ExternalEvidence"
	body.SchemaVersion = 1
	if err := validateEvidence(body); err != nil {
		return SignedExternalEvidence{}, err
	}
	data, err := canonical(body)
	if err != nil {
		return SignedExternalEvidence{}, err
	}
	if len(data) > MaxObjectBytes {
		return SignedExternalEvidence{}, errors.New("external evidence too large")
	}
	return SignedExternalEvidence{Body: data, KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(externalEvidenceDomain), data...)))}, nil
}

func VerifyExternalEvidence(signed SignedExternalEvidence, keys []EvidenceKey, expected EvidenceExpectation, now time.Time) (VerifiedExternalEvidence, error) {
	var out VerifiedExternalEvidence
	if len(signed.Body) == 0 || len(signed.Body) > MaxObjectBytes || len(signed.Signature) != base64.StdEncoding.EncodedLen(ed25519.SignatureSize) || !identifier.MatchString(signed.KeyID) {
		return out, errors.New("external evidence size rejected")
	}
	data, err := spec.CanonicalRaw(signed.Body)
	if err != nil || !bytes.Equal(data, signed.Body) {
		return out, errors.New("external evidence must use exact canonical JSON")
	}
	var body ExternalEvidence
	if err = strictJSON(signed.Body, &body); err != nil {
		return out, err
	}
	if err = validateEvidence(body); err != nil {
		return out, err
	}
	if body.Project != expected.Project || body.Site != expected.Site || body.Subject != expected.Subject || body.Scope != expected.Scope {
		return out, errors.New("external evidence does not match the exact expected subject and scope")
	}
	observed, _ := time.Parse(time.RFC3339Nano, body.ObservedAt)
	expires, _ := time.Parse(time.RFC3339Nano, body.ExpiresAt)
	if now.Before(observed) || !now.Before(expires) {
		return out, errors.New("external evidence scope is expired or observed in the future")
	}
	if err = validateEvidenceKeys(keys); err != nil {
		return out, err
	}
	var trusted *EvidenceKey
	for i := range keys {
		if keys[i].ID == signed.KeyID {
			trusted = &keys[i]
		}
	}
	if trusted == nil || trusted.Revoked || trusted.Producer != body.Producer.Name || !contains(trusted.Versions, body.Producer.Version) || !contains(trusted.Projects, body.Project) || !contains(trusted.Sites, body.Site) || !contains(trusted.Applications, body.Subject.Application) || !contains(trusted.Profiles, body.Subject.Profile) || !contains(trusted.Scopes, body.Scope) {
		return out, errors.New("external evidence producer key is not admitted for this scope")
	}
	if trusted.NotAfter != "" {
		expiry, _ := time.Parse(time.RFC3339Nano, trusted.NotAfter)
		if !now.Before(expiry) {
			return out, errors.New("external evidence key scope expired")
		}
	}
	pub, _ := base64.StdEncoding.DecodeString(trusted.PublicKey)
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(pub, append([]byte(externalEvidenceDomain), signed.Body...), signature) {
		return out, errors.New("external evidence signature rejected")
	}
	digest, err := spec.Digest(signed)
	if err != nil {
		return out, err
	}
	notice := "Producer claim retained without strengthening it. This attachment does not change run acceptance, authorize execution, or establish live health."
	if body.RuntimeCapture != nil {
		notice += " Runtime outcomes and confidence are producer claims; attempts do not establish functional dependence or network independence. Declared DNS/TCP/UDP scope is not exhaustive protocol coverage."
		if len(body.RuntimeCapture.Observations) == 0 {
			notice += " No observations in declared capture scope; this is not proof of zero external dependency."
		}
	}
	return VerifiedExternalEvidence{APIVersion: spec.APIVersion, Kind: "ExternalEvidenceVerification", Digest: digest, Integrity: "verified", Acceptance: "attached_evidence_only", Evidence: body, Notice: notice}, nil
}

func (s *Server) admitExternalEvidence(ctx context.Context, a Actor, b []byte) (any, error) {
	var request struct {
		Project   string                 `json:"project"`
		Site      string                 `json:"site"`
		RunDigest string                 `json:"runDigest"`
		Scope     string                 `json:"scope"`
		Evidence  SignedExternalEvidence `json:"evidence"`
	}
	if err := strictJSON(b, &request); err != nil {
		return nil, err
	}
	if !a.can(request.Project, request.Site, "import") {
		return nil, errDenied
	}
	observation, err := s.cfg.Store.Observation(ctx, request.Project, request.Site, request.RunDigest)
	if err != nil {
		return nil, err
	}
	subject, err := SubjectForObservation(observation)
	if err != nil {
		return nil, err
	}
	verified, err := VerifyExternalEvidence(request.Evidence, s.cfg.EvidenceKeys, EvidenceExpectation{Project: request.Project, Site: request.Site, Subject: subject, Scope: request.Scope}, s.cfg.Now())
	if err != nil {
		return nil, err
	}
	record := externalEvidenceRecord{APIVersion: spec.APIVersion, Kind: "ExternalEvidenceRecord", RunDigest: request.RunDigest, Signed: request.Evidence, VerifiedAt: s.cfg.Now().UTC().Format(time.RFC3339Nano)}
	body, err := canonical(record)
	if err != nil {
		return nil, err
	}
	stored, err := s.cfg.Store.Put(ctx, a.ID, Record{Project: request.Project, Site: request.Site, Kind: "Evidence", Body: body})
	if err != nil {
		return nil, err
	}
	return struct {
		Record       StoredRecord             `json:"record"`
		Verification VerifiedExternalEvidence `json:"verification"`
	}{stored, verified}, nil
}

// VerifyEvidence rechecks expiry, producer admission, and exact linked run scope
// on every read. A historical admission label is never a current verifier.
func (s *Store) VerifyEvidence(ctx context.Context, project, site, digest string, keys []EvidenceKey, now time.Time) (VerifiedExternalEvidence, error) {
	stored, err := s.Get(ctx, project, site, "Evidence", digest)
	if err != nil {
		return VerifiedExternalEvidence{}, err
	}
	var record externalEvidenceRecord
	if err = strictJSON(stored.Record.Body, &record); err != nil {
		return VerifiedExternalEvidence{}, err
	}
	if record.APIVersion != spec.APIVersion || record.Kind != "ExternalEvidenceRecord" {
		return VerifiedExternalEvidence{}, errors.New("record is not a typed external evidence admission")
	}
	o, err := s.Observation(ctx, project, site, record.RunDigest)
	if err != nil {
		return VerifiedExternalEvidence{}, err
	}
	subject, err := SubjectForObservation(o)
	if err != nil {
		return VerifiedExternalEvidence{}, err
	}
	var body ExternalEvidence
	if err = strictJSON(record.Signed.Body, &body); err != nil {
		return VerifiedExternalEvidence{}, err
	}
	return VerifyExternalEvidence(record.Signed, keys, EvidenceExpectation{Project: project, Site: site, Subject: subject, Scope: body.Scope}, now)
}
