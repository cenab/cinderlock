package engine

import (
	"crypto/ed25519"
	"encoding/base64"
	"slices"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func (e *Engine) authorize(p spec.Plan, policy spec.TrustPolicy, a *spec.Authorization, approved bool) (string, error) {
	digest, err := spec.Digest(p)
	if err != nil {
		return "", err
	}
	if a == nil {
		if policy.Spec.RequireAuthorization || !policy.Spec.AllowInteractive || !approved {
			return "", spec.Err(16, "this exact plan requires site-authorized execution approval")
		}
		return "interactive:" + digest, nil
	}
	if err := spec.ValidateHeader(a.Header, "Authorization"); err != nil {
		return "", err
	}
	if a.PlanDigest != digest || a.PlanKind != p.Kind || a.TargetID != p.Snapshot.TargetID || a.PolicyDigest != p.PolicyDigest || a.PolicyEpoch != policy.Spec.Epoch || a.Nonce == "" {
		return "", spec.Err(16, "authorization does not bind the current plan, target and policy")
	}
	expires, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err != nil || !time.Now().Before(expires) {
		return "", spec.Err(16, "authorization expired or invalid")
	}
	for _, capability := range spec.PlanActions(p) {
		if !slices.Contains(a.Actions, capability) {
			return "", spec.Err(16, "authorization does not cover action %s", capability)
		}
	}
	body, err := spec.AuthorizationBytes(*a)
	if err != nil {
		return "", err
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature.Signature)
	if err != nil || a.Signature.Algorithm != "Ed25519" {
		return "", spec.Err(16, "invalid execution authorization signature")
	}
	valid := false
	for _, key := range policy.Spec.Keys {
		if key.ID != a.Signature.KeyID || key.Revoked || !slices.Contains(key.Roles, "approval") || !matches(key.Applications, p.Metadata.Application) || !matches(key.Channels, p.Metadata.Channel) {
			continue
		}
		public, err := bundle.ParsePublicKey(key.PublicKey)
		if err != nil {
			return "", err
		}
		if ed25519.Verify(public, append([]byte(spec.AuthorizationDomain+"\x00"), body...), sig) {
			valid = true
		}
	}
	if !valid {
		return "", spec.Err(16, "authorization signer lacks independently admitted approval authority")
	}
	return a.Nonce, nil
}

func matches(values []string, value string) bool {
	return slices.Contains(values, "*") || slices.Contains(values, value)
}

func authorizationExpiry(a *spec.Authorization) string {
	if a == nil {
		return "interactive"
	}
	return a.ExpiresAt
}
