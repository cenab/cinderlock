package spec

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func ValidDigest(s string) bool { return digestPattern.MatchString(s) }
func ValidateHeader(h Header, kind string) error {
	if h.APIVersion != APIVersion || h.Kind != kind || h.SchemaVersion != 1 {
		return Err(2, "expected %s %s schemaVersion 1", APIVersion, kind)
	}
	return nil
}
func ValidateRelease(r Release) error {
	if e := ValidateHeader(r.Header, "Release"); e != nil {
		return e
	}
	if !identifier.MatchString(r.Metadata.Application) || r.Metadata.Version == "" || !identifier.MatchString(r.Metadata.Channel) || r.Metadata.Sequence < 1 {
		return Err(2, "release needs application, version, channel and positive sequence")
	}
	if r.Spec.Profile == "" || r.Spec.Deployment.Chart == "" {
		return Err(2, "profile and packaged chart are required")
	}
	if r.Spec.Deployment.Type != "helm" && r.Spec.Deployment.Type != "gitops" {
		return Err(2, "deployment type must be helm or gitops")
	}
	if err := ValidateConfigurationContract(r.Spec.Deployment); err != nil {
		return err
	}
	assets := map[string]bool{}
	for _, a := range r.Spec.Assets {
		if !identifier.MatchString(a.ID) || strings.HasPrefix(a.ID, "cinderlock-") || assets[a.ID] || a.Source == "" {
			return Err(2, "invalid, duplicate, reserved, or sourceless asset %q", a.ID)
		}
		assets[a.ID] = true
		switch a.Type {
		case "image", "file", "model-tree", "file-tree", "model", "directory":
		default:
			return Err(2, "unsupported asset type %q", a.Type)
		}
		if a.Digest != "" && !ValidDigest(a.Digest) {
			return Err(2, "invalid asset digest %s", a.ID)
		}
		if u, e := url.Parse(a.Source); e == nil && (u.User != nil || u.RawQuery != "") {
			return Err(2, "credential-bearing asset URL is not portable")
		}
	}
	for _, id := range []string{r.Spec.AIProfile.ModelAsset, r.Spec.AIProfile.TokenizerAsset, r.Spec.AIProfile.RuntimeAsset, r.Spec.AIProfile.AdapterAsset} {
		if id != "" && !assets[id] {
			return Err(2, "AI profile references missing asset %q", id)
		}
	}
	for _, b := range r.Spec.Deployment.ImageBindings {
		if !assets[b.Asset] || b.ValuesPath == "" {
			return Err(2, "invalid image binding %q", b.Asset)
		}
	}
	ops := map[string]bool{}
	for _, o := range r.Spec.Operations {
		if ops[o.ID] {
			return Err(2, "duplicate operation %q", o.ID)
		}
		ops[o.ID] = true
		if e := ValidateOperation(o); e != nil {
			return e
		}
	}
	for _, o := range r.Spec.Operations {
		for _, d := range o.DependsOn {
			if !ops[d] || d == o.ID {
				return Err(2, "operation %s has invalid dependency %s", o.ID, d)
			}
		}
	}
	if e := operationDAG(r.Spec.Operations); e != nil {
		return e
	}
	checks := map[string]bool{}
	for _, c := range r.Spec.Checks {
		if checks[c.ID] {
			return Err(2, "duplicate check %s", c.ID)
		}
		checks[c.ID] = true
		if e := ValidateCheck(c); e != nil {
			return e
		}
		for _, a := range c.Fixtures {
			if !assets[a] {
				return Err(2, "check %s references missing fixture %s", c.ID, a)
			}
		}
	}
	if err := validateObservationBudget(r.Spec.Checks); err != nil {
		return err
	}
	if len(r.Spec.RequiredChecks) == 0 {
		return Err(2, "at least one required workflow is mandatory")
	}
	workflowRequired := false
	for _, c := range r.Spec.Checks {
		if c.Domain == "workflow" && (c.Required || containsString(r.Spec.RequiredChecks, c.ID)) {
			workflowRequired = true
		}
	}
	if !workflowRequired {
		return Err(2, "at least one required application workflow check is mandatory")
	}
	for _, c := range r.Spec.RequiredChecks {
		if !checks[c] {
			return Err(2, "required check %s is missing", c)
		}
	}
	recoveries := map[string]bool{}
	for _, rec := range r.Spec.Recovery {
		if !identifier.MatchString(rec.ID) || recoveries[rec.ID] || rec.ToRelease == "" {
			return Err(2, "invalid recovery %s", rec.ID)
		}
		recoveries[rec.ID] = true
		recOps := map[string]bool{}
		for _, o := range rec.Operations {
			if recOps[o.ID] {
				return Err(2, "recovery %s has duplicate operation %s", rec.ID, o.ID)
			}
			recOps[o.ID] = true
			if e := ValidateOperation(o); e != nil {
				return e
			}
		}
		for _, o := range rec.Operations {
			for _, dep := range o.DependsOn {
				if !recOps[dep] || dep == o.ID {
					return Err(2, "recovery %s operation %s has invalid dependency %s", rec.ID, o.ID, dep)
				}
			}
		}
		if err := operationDAG(rec.Operations); err != nil {
			return err
		}
		recChecks := map[string]bool{}
		for _, c := range rec.Checks {
			if recChecks[c.ID] {
				return Err(2, "recovery %s has duplicate check %s", rec.ID, c.ID)
			}
			recChecks[c.ID] = true
			if e := ValidateCheck(c); e != nil {
				return e
			}
		}
		if err := validateObservationBudget(rec.Checks); err != nil {
			return err
		}
	}
	if len(r.Spec.Transitions) == 0 {
		return Err(2, "at least one explicit directional transition is required")
	}
	seen := map[string]bool{}
	for _, t := range r.Spec.Transitions {
		if !identifier.MatchString(t.ID) || seen[t.ID] || t.FromRelease == "" || !recoveries[t.Recovery] {
			return Err(2, "transition %q needs unique ID, fromRelease and declared recovery", t.ID)
		}
		seen[t.ID] = true
		for _, id := range t.Operations {
			if !ops[id] {
				return Err(2, "transition %s references missing operation %s", t.ID, id)
			}
		}
		if t.FromEmbeddingRevision != "" && t.FromEmbeddingRevision != r.Spec.AIProfile.EmbeddingRevision && !ops[t.ReindexOperation] {
			return Err(2, "embedding transition requires explicit reindex operation")
		}
	}
	return validateReleaseContracts(r)
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
func ValidateOperation(o Operation) error {
	if o.ModelSubPath != "" && (o.Type != "seed" || o.ModelSubPath == "." || !SafePath(o.ModelSubPath)) {
		return Err(2, "modelSubPath must be a confined relative directory on a seed operation")
	}
	if !identifier.MatchString(o.ID) {
		return Err(2, "invalid operation ID %q", o.ID)
	}
	switch o.Type {
	case "job", "migrate", "backup", "reindex", "helm", "restart", "seed", "import", "gitops":
	default:
		return Err(2, "unsupported operation type %q", o.Type)
	}
	if err := validateScriptContract(o); err != nil {
		return err
	}
	if o.TimeoutSeconds < 0 || o.TimeoutSeconds > 86400 {
		return Err(2, "invalid operation timeout")
	}
	if o.Destructive && o.Type == "import" {
		return Err(2, "artifact import cannot declare data destruction")
	}
	return nil
}
func ValidateCheck(c Check) error {
	if !identifier.MatchString(c.ID) {
		return Err(2, "invalid check ID")
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > 86400 {
		return Err(2, "invalid check timeout")
	}
	if c.Type != "endpoint" && (c.CASecretRef != "" || c.AuthorizationSecretRef != "") {
		return Err(2, "CA and authorization role references require the fixed endpoint adapter")
	}
	if err := validateCheckScript(c); err != nil {
		return err
	}
	switch c.Domain {
	case "integrity", "readiness", "workflow", "recovery":
	default:
		return Err(2, "invalid check domain %q", c.Domain)
	}
	switch c.Type {
	case "endpoint":
		if err := validateEndpointCheck(c); err != nil {
			return err
		}
	case "http":
		if len(c.Command) != 0 || c.Method != "" && c.Method != "GET" && c.Method != "HEAD" {
			return Err(2, "HTTP check requires the fixed GET or HEAD adapter")
		}
		u, e := url.Parse(c.URL)
		if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			return Err(2, "invalid HTTP check URL")
		}
		if c.ExpectedStatus < 100 || c.ExpectedStatus > 599 {
			return Err(2, "HTTP check needs expectedStatus")
		}
	case "job":
		if c.Image == "" || !validContractArgv(c.Command, true) {
			return Err(2, "job check requires locked image and bounded explicit argv without NUL bytes")
		}
	default:
		return Err(2, "unsupported check type %q", c.Type)
	}
	if c.ObservationContract != nil {
		if c.Type != "job" || c.ExpectedExitCode != 0 {
			return Err(2, "observations require a successful Job check with a bounded timeout")
		}
		return ValidateObservationContract(*c.ObservationContract)
	}
	return nil
}
func operationDAG(ops []Operation) error {
	m := map[string]Operation{}
	for _, o := range ops {
		m[o.ID] = o
	}
	state := map[string]int{}
	var visit func(string) error
	visit = func(id string) error {
		if state[id] == 1 {
			return Err(2, "operation dependency cycle")
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		for _, dep := range m[id].DependsOn {
			if e := visit(dep); e != nil {
				return e
			}
		}
		state[id] = 2
		return nil
	}
	for id := range m {
		if e := visit(id); e != nil {
			return e
		}
	}
	return nil
}
func ValidatePolicy(p TrustPolicy) error {
	if e := ValidateHeader(p.Header, "TrustPolicy"); e != nil {
		return e
	}
	if p.Spec.Epoch < 1 || len(p.Spec.Keys) == 0 {
		return Err(2, "trust policy needs epoch and independently admitted keys")
	}
	seen := map[string]bool{}
	for _, k := range p.Spec.Keys {
		b, e := base64.StdEncoding.DecodeString(k.PublicKey)
		if !identifier.MatchString(k.ID) || seen[k.ID] || e != nil || len(b) != ed25519.PublicKeySize || len(k.Applications) == 0 || len(k.Channels) == 0 {
			return Err(2, "invalid or unscoped trust key %q", k.ID)
		}
		seen[k.ID] = true
	}
	if p.Spec.ExpiresAt != "" {
		t, e := time.Parse(time.RFC3339, p.Spec.ExpiresAt)
		if e != nil || !time.Now().Before(t) {
			return Err(16, "trust policy expired or invalid")
		}
	}
	return nil
}
func ValidateSite(s Site) error {
	if e := ValidateHeader(s.Header, "Site"); e != nil {
		return e
	}
	if !identifier.MatchString(s.Metadata.Name) || s.Spec.Kubeconfig == "" || s.Spec.Context == "" || s.Spec.Namespace == "" || s.Spec.ReleaseName == "" || s.Spec.TrustPolicy == "" || s.Spec.Profile == "" {
		return Err(2, "site needs name, explicit kubeconfig/context, namespace, releaseName, trustPolicy and profile")
	}
	return nil
}
func SafePath(s string) bool {
	return s != "" && !strings.ContainsAny(s, "\\\x00\r\n") && !strings.HasPrefix(s, "/") && path.Clean(s) == s && s != ".." && !strings.HasPrefix(s, "../")
}
func AuthorizationBytes(a Authorization) ([]byte, error) {
	b, e := json.Marshal(a)
	if e != nil {
		return nil, e
	}
	var body map[string]json.RawMessage
	if e = json.Unmarshal(b, &body); e != nil {
		return nil, e
	}
	delete(body, "signature")
	return Canonical(body)
}
func SignAuthorization(a *Authorization, key ed25519.PrivateKey, keyID string) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key")
	}
	b, e := AuthorizationBytes(*a)
	if e != nil {
		return e
	}
	message := append([]byte(AuthorizationDomain+"\x00"), b...)
	a.Signature = Signature{KeyID: keyID, Algorithm: "Ed25519", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))}
	return nil
}
