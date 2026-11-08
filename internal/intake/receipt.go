package intake

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

const ReceiptDomain = "cinderlock.custody-receipt.v1"
const Genesis = "genesis"
const MaxReceiptBytes = 64 << 10
const MaxChainReceipts int64 = 1000000

type CustodyKey struct {
	ID           string   `json:"id"`
	PublicKey    string   `json:"publicKey"`
	Custodians   []string `json:"custodians"`
	Sites        []string `json:"sites"`
	Applications []string `json:"applications"`
	Profiles     []string `json:"profiles"`
	NotBefore    string   `json:"notBefore,omitempty"`
	ExpiresAt    string   `json:"expiresAt"`
	Revoked      bool     `json:"revoked,omitempty"`
}
type CustodyPolicy struct {
	spec.Header
	Keys []CustodyKey `json:"keys"`
}
type Claim struct {
	Custodian string `json:"custodian"`
	Site      string `json:"site"`
	Sequence  int64  `json:"sequence"`
	ExpiresAt string `json:"expiresAt"`
}
type ReceiptBody struct {
	spec.Header
	ManifestDigest     string `json:"manifestDigest"`
	BundleDigest       string `json:"bundleDigest"`
	Profile            string `json:"profile"`
	PreviousDigest     string `json:"previousDigest"`
	Sequence           int64  `json:"sequence"`
	Issuer             string `json:"issuer"`
	Custodian          string `json:"custodian"`
	Site               string `json:"site"`
	RecordedAt         string `json:"recordedAt"`
	ExpiresAt          string `json:"expiresAt"`
	Scope              string `json:"scope"`
	PhysicalCustody    string `json:"physicalCustody"`
	Approval           string `json:"approval"`
	ExecutionAuthority string `json:"executionAuthority"`
}
type SignedReceipt struct {
	spec.Header
	Body      json.RawMessage `json:"body"`
	Signature spec.Signature  `json:"signature"`
}
type Verification struct {
	spec.Header
	ReceiptDigest      string `json:"receiptDigest"`
	ManifestDigest     string `json:"manifestDigest"`
	BundleDigest       string `json:"bundleDigest"`
	Profile            string `json:"profile"`
	PreviousDigest     string `json:"previousDigest"`
	Sequence           int64  `json:"sequence"`
	Issuer             string `json:"issuer"`
	Custodian          string `json:"declaredCustodian"`
	Site               string `json:"declaredSite"`
	Signature          string `json:"signature"`
	ExpiresAt          string `json:"expiresAt"`
	Anchored           bool   `json:"anchored"`
	PhysicalCustody    string `json:"physicalCustody"`
	Approval           string `json:"approval"`
	ExecutionAuthority string `json:"executionAuthority"`
	Notice             string `json:"notice"`
}

func policyKey(policy CustodyPolicy, id string, body ReceiptBody, vendor spec.TrustPolicy, now time.Time) (ed25519.PublicKey, error) {
	if vendor.Spec.ExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339Nano, vendor.Spec.ExpiresAt)
		if err != nil || !now.Before(expiry) {
			return nil, errors.New("release trust expired before the custody decision")
		}
	}
	if err := spec.ValidateHeader(policy.Header, "CustodyPolicy"); err != nil {
		return nil, err
	}
	if len(policy.Keys) == 0 || len(policy.Keys) > 256 {
		return nil, errors.New("custody policy key count exceeds bounds")
	}
	seen := map[string]bool{}
	var selected *CustodyKey
	for i, k := range policy.Keys {
		if !identifier.MatchString(k.ID) || seen[k.ID] || len(k.PublicKey) > 16384 || len(k.Custodians) == 0 || len(k.Sites) == 0 || len(k.Applications) == 0 || len(k.Profiles) == 0 {
			return nil, errors.New("custody key needs a unique ID and explicit bounded scopes")
		}
		seen[k.ID] = true
		for _, scope := range [][]string{k.Custodians, k.Sites, k.Applications, k.Profiles} {
			if len(scope) > 128 {
				return nil, errors.New("custody key scope exceeds bounds")
			}
			for _, value := range scope {
				if value == "" || len(value) > 256 {
					return nil, errors.New("empty or excessive custody key scope")
				}
			}
		}
		if _, err := bundle.ParsePublicKey(k.PublicKey); err != nil {
			return nil, err
		}
		if _, err := time.Parse(time.RFC3339Nano, k.ExpiresAt); err != nil {
			return nil, errors.New("custody key needs a valid expiry")
		}
		if k.NotBefore != "" {
			if _, err := time.Parse(time.RFC3339Nano, k.NotBefore); err != nil {
				return nil, errors.New("invalid custody key start time")
			}
		}
		if k.ID == id {
			selected = &policy.Keys[i]
		}
	}
	if selected == nil || selected.Revoked || !has(selected.Custodians, body.Custodian) || !has(selected.Sites, body.Site) || !has(selected.Applications, body.Metadata.Application) || !has(selected.Profiles, body.Profile) {
		return nil, errors.New("custody issuer is not admitted for the declared identity and profile scope")
	}
	expiry, _ := time.Parse(time.RFC3339Nano, selected.ExpiresAt)
	receiptExpiry, _ := time.Parse(time.RFC3339Nano, body.ExpiresAt)
	if !now.Before(expiry) || receiptExpiry.After(expiry) {
		return nil, errors.New("custody key is expired or does not cover the receipt lifetime")
	}
	if selected.NotBefore != "" {
		start, _ := time.Parse(time.RFC3339Nano, selected.NotBefore)
		recorded, _ := time.Parse(time.RFC3339Nano, body.RecordedAt)
		if now.Before(start) || recorded.Before(start) {
			return nil, errors.New("custody key is not valid for the receipt time")
		}
	}
	key, _ := bundle.ParsePublicKey(selected.PublicKey)
	for _, releaseKey := range vendor.Spec.Keys {
		public, err := bundle.ParsePublicKey(releaseKey.PublicKey)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(public, key) {
			return nil, errors.New("custody key must be independent from supplied release-trust keys")
		}
	}
	return key, nil
}

func has(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func validPrevious(previous string, sequence int64) bool {
	return sequence > 0 && sequence <= MaxChainReceipts && (previous == Genesis && sequence == 1 || spec.ValidDigest(previous) && sequence >= 2)
}

func validateReceiptBody(m Manifest, b ReceiptBody, previous string, now time.Time) error {
	if err := spec.ValidateHeader(b.Header, "CustodyReceipt"); err != nil {
		return err
	}
	identity, err := spec.Digest(m)
	if err != nil {
		return err
	}
	if b.ManifestDigest != identity || b.BundleDigest != m.BundleDigest || b.Metadata != m.Metadata || b.Profile != m.Profile {
		return errors.New("custody receipt does not bind this exact manifest, bundle, release, and profile")
	}
	if !validPrevious(previous, b.Sequence) || b.PreviousDigest != previous {
		return errors.New("custody previous head or sequence does not match the caller's anchor")
	}
	if !identifier.MatchString(b.Issuer) || !identifier.MatchString(b.Custodian) || !identifier.MatchString(b.Site) {
		return errors.New("custody identity labels must be bounded declared identifiers")
	}
	observed, err := time.Parse(time.RFC3339Nano, b.RecordedAt)
	if err != nil || observed.After(now) {
		return errors.New("custody recorded time is invalid or in the future")
	}
	expiry, err := time.Parse(time.RFC3339Nano, b.ExpiresAt)
	if err != nil || !expiry.After(observed) || !now.Before(expiry) {
		return errors.New("custody receipt has expired or invalid lifetime")
	}
	if b.Scope != "local-manifest-record" || b.PhysicalCustody != "not_observed" || b.Approval != "not_attested" || b.ExecutionAuthority != "none" {
		return errors.New("custody receipt cannot assert physical custody, approval, or execution authority")
	}
	return nil
}

func SignReceipt(ctx context.Context, path string, vendor spec.TrustPolicy, m Manifest, policy CustodyPolicy, claim Claim, previous, keyID string, key ed25519.PrivateKey, now func() time.Time) (SignedReceipt, error) {
	if err := VerifyManifest(ctx, path, vendor, m); err != nil {
		return SignedReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return SignedReceipt{}, err
	}
	if now == nil {
		now = time.Now
	}
	at := now()
	if len(key) != ed25519.PrivateKeySize {
		return SignedReceipt{}, errors.New("custody signer must be Ed25519")
	}
	digest, err := spec.Digest(m)
	if err != nil {
		return SignedReceipt{}, err
	}
	body := ReceiptBody{Header: spec.NewHeader("CustodyReceipt"), ManifestDigest: digest, BundleDigest: m.BundleDigest, PreviousDigest: previous, Sequence: claim.Sequence, Issuer: keyID, Custodian: claim.Custodian, Site: claim.Site, RecordedAt: at.UTC().Format(time.RFC3339Nano), ExpiresAt: claim.ExpiresAt, Scope: "local-manifest-record", PhysicalCustody: "not_observed", Approval: "not_attested", ExecutionAuthority: "none"}
	body.Metadata = m.Metadata
	body.Profile = m.Profile
	if err = validateReceiptBody(m, body, previous, at); err != nil {
		return SignedReceipt{}, err
	}
	public, err := policyKey(policy, keyID, body, vendor, at)
	if err != nil {
		return SignedReceipt{}, err
	}
	if !bytes.Equal(public, key.Public().(ed25519.PublicKey)) {
		return SignedReceipt{}, errors.New("custody private key does not match its independent admission")
	}
	data, err := spec.Canonical(body)
	if err != nil {
		return SignedReceipt{}, err
	}
	if len(data) > MaxReceiptBytes {
		return SignedReceipt{}, errors.New("custody receipt exceeds size limit")
	}
	signature := ed25519.Sign(key, append([]byte(ReceiptDomain+"\x00"), data...))
	envelope := SignedReceipt{Header: spec.NewHeader("SignedCustodyReceipt"), Body: data, Signature: spec.Signature{KeyID: keyID, Algorithm: "Ed25519", Signature: base64.StdEncoding.EncodeToString(signature)}}
	envelope.Metadata = body.Metadata
	return envelope, nil
}

func verifyReceipt(m Manifest, envelope SignedReceipt, policy CustodyPolicy, vendor spec.TrustPolicy, previous string, now time.Time) (Verification, error) {
	var out Verification
	if err := ValidateManifest(m); err != nil {
		return out, err
	}
	if err := spec.ValidateHeader(envelope.Header, "SignedCustodyReceipt"); err != nil {
		return out, err
	}
	if len(envelope.Body) == 0 || len(envelope.Body) > MaxReceiptBytes || envelope.Signature.Algorithm != "Ed25519" || len(envelope.Signature.Signature) != base64.StdEncoding.EncodedLen(ed25519.SignatureSize) {
		return out, errors.New("custody receipt envelope exceeds bounds or uses an unsupported signature")
	}
	data, err := spec.CanonicalRaw(envelope.Body)
	if err != nil || !bytes.Equal(data, envelope.Body) {
		return out, errors.New("custody receipt body must use exact canonical JSON")
	}
	var body ReceiptBody
	if err = spec.Decode(data, &body); err != nil {
		return out, err
	}
	if err = validateReceiptBody(m, body, previous, now); err != nil {
		return out, err
	}
	if envelope.Signature.KeyID != body.Issuer || envelope.Metadata != body.Metadata {
		return out, errors.New("custody issuer or envelope identity mismatch")
	}
	public, err := policyKey(policy, envelope.Signature.KeyID, body, vendor, now)
	if err != nil {
		return out, err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature.Signature)
	if err != nil || !ed25519.Verify(public, append([]byte(ReceiptDomain+"\x00"), data...), signature) {
		return out, errors.New("custody receipt signature rejected")
	}
	digest, err := spec.Digest(envelope)
	if err != nil {
		return out, err
	}
	out = Verification{Header: spec.NewHeader("CustodyReceiptVerification"), ReceiptDigest: digest, ManifestDigest: body.ManifestDigest, BundleDigest: body.BundleDigest, PreviousDigest: previous, Sequence: body.Sequence, Issuer: body.Issuer, Custodian: body.Custodian, Site: body.Site, ExpiresAt: body.ExpiresAt, Signature: "verified", PhysicalCustody: "not_observed", Approval: "not_attested", ExecutionAuthority: "none", Notice: "Signature proves the bound bytes and scoped admitted key. Identity labels and local timestamps are declared. Physical transfer and human approval are unobserved. Stateless checks need a trusted advancing head to prevent replay; no execution admission is granted."}
	out.Metadata = m.Metadata
	out.Profile = m.Profile
	return out, nil
}

func VerifyReceipt(ctx context.Context, path string, vendor spec.TrustPolicy, m Manifest, envelope SignedReceipt, policy CustodyPolicy, previous string, now func() time.Time) (Verification, error) {
	if err := VerifyManifest(ctx, path, vendor, m); err != nil {
		return Verification{}, err
	}
	if err := ctx.Err(); err != nil {
		return Verification{}, err
	}
	if now == nil {
		now = time.Now
	}
	return verifyReceipt(m, envelope, policy, vendor, previous, now())
}
