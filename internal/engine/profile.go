package engine

import (
	"context"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/modelstage"
	"github.com/cenab/cinderlock/internal/spec"
)

// ExecutionFindings checks every selected recipe before the first mutation.
// Permission, admission and actual workflow observations remain separate checks.
func (e *Engine) ExecutionFindings(ctx context.Context, p spec.Plan, v *bundle.Verified) []spec.Finding {
	findings := []spec.Finding{}
	block := func(code, message string) {
		findings = append(findings, spec.Finding{Code: code, Severity: "blocker", Message: message, Source: "supported execution profile"})
	}
	if ctx.Err() != nil {
		block("PROFILE_INTERRUPTED", "execution preflight was interrupted")
		return findings
	}
	checkImage := func(ref, id, code string) {
		if _, err := e.image(v, ref); err != nil {
			block(code, "selected recipe needs a locked internal image: "+id)
		}
	}
	available := map[string]bool{}
	for _, fact := range p.Snapshot.Facts {
		if fact.Status == "known" {
			available[fact.Name] = true
		}
	}
	checkSecrets := func(refs []string, id string) {
		for _, name := range refs {
			if reservedJobEnvironment(strings.ToUpper(strings.ReplaceAll(name, "-", "_"))) {
				block("JOB_SECRET_ENV_CONFLICT", "selected Job secret conflicts with fixed execution provenance: "+id+"/"+name)
			}
			ref, ok := e.Site.Spec.SecretRefs[name]
			if !ok {
				block("JOB_SECRET_MISSING", "selected Job secret reference is missing: "+id+"/"+name)
				continue
			}
			if ref.File != "" {
				block("JOB_SECRET_FILE_UNSUPPORTED", "selected Job requires a customer-managed Kubernetes Secret, not a local file: "+id+"/"+name)
				continue
			}
			if ref.Name == "" || ref.Key == "" || ref.Namespace != "" && ref.Namespace != e.Site.Spec.Namespace {
				block("JOB_SECRET_SCOPE_UNSUPPORTED", "selected Job secret needs an explicit name/key in the target namespace: "+id+"/"+name)
			}
			if !available["secret/"+name] {
				block("JOB_SECRET_UNAVAILABLE", "selected Job secret is absent, denied or unreadable: "+id+"/"+name)
			}
		}
	}
	volume := func(o spec.Operation) {
		if (o.PVC == "") != (o.MountPath == "") || o.PVC != "" && (!path.IsAbs(o.MountPath) || path.Clean(o.MountPath) != o.MountPath || o.MountPath == "/" || o.MountPath == "/tmp" || strings.ContainsRune(o.MountPath, '\x00')) {
			block("JOB_VOLUME_UNSUPPORTED", "selected Job needs a named PVC and a clean absolute non-root mount distinct from /tmp: "+o.ID)
		}
	}
	seeds := map[string]bool{}
	for _, o := range p.Operations {
		if o.ExpectedExitCode != 0 {
			block("OPERATION_EXIT_UNSUPPORTED", "selected operation requires unsupported nonzero expected exit code: "+o.ID)
		}
		if o.TimeoutSeconds < 0 || o.TimeoutSeconds > 86400 {
			block("OPERATION_TIMEOUT_UNSUPPORTED", "selected operation timeout exceeds the supported profile: "+o.ID)
		}
		checkSecrets(o.SecretRefs, o.ID)
		switch {
		case o.Type == "seed" && len(o.Command) == 0:
			if !spec.ValidDigest(e.Site.Spec.HelperImage) {
				block("MODEL_HELPER_PIN_MISSING", "native model staging requires an independently admitted exact helper manifest digest")
			}
			if o.Image != "" || len(o.Args) != 0 || len(o.SecretRefs) != 0 {
				block("NATIVE_SEED_PROFILE_UNSUPPORTED", "native model staging does not execute carrier images, arguments or secrets: "+o.ID)
			}
			if !nativeMountSupported(o.MountPath) {
				block("NATIVE_SEED_MOUNT_UNSUPPORTED", "native model mount cannot obscure its helper executable or signed manifest")
			}
			volume(o)
		case isJob(o.Type), o.Type == "probe", o.Type == "seed":
			checkImage(o.Image, o.ID, "OPERATION_IMAGE_MISSING")
			if len(o.Command) == 0 || o.Command[0] == "" {
				block("OPERATION_COMMAND_MISSING", "selected Job needs an explicit entrypoint: "+o.ID)
			}
			volume(o)
		case o.Type == "import":
			if _, err := importTargets(v, o.Asset); err != nil {
				block("IMPORT_ASSET_MISSING", "selected import has no matching locked image targets: "+o.ID)
			}
			if e.Site.Spec.Registry == "" || strings.ContainsAny(e.Site.Spec.Registry, "@?#") || strings.Contains(e.Site.Spec.Registry, "://") {
				block("REGISTRY_TARGET_UNSUPPORTED", "image import needs an internal registry/repository without a URL scheme or embedded credentials")
			}
			if _, err := e.registryOptions(ctx); err != nil {
				block("REGISTRY_AUTH_UNSUPPORTED", "registry authentication is unavailable or outside the supported credential profile")
			}
		case o.Type == "helm", o.Type == "restart", o.Type == "uninstall":
			if len(o.Command) > 0 || len(o.Args) > 0 {
				block("OPERATION_COMMAND_IGNORED", "selected adapter does not execute authored commands or arguments: "+o.ID)
			}
			if o.Type == "restart" && o.Service == "" {
				block("RESTART_TARGET_MISSING", "restart needs an explicit managed Deployment name")
			}
		case o.Type == "gitops":
			block("GITOPS_EXTERNAL_OWNER", "GitOps changes must be delivered through their declared controller owner")
		default:
			block("OPERATION_UNSUPPORTED", "selected operation is outside the supported execution profile: "+o.ID)
		}
		if o.Type != "seed" {
			continue
		}
		checkImage(e.Site.Spec.HelperImage, o.ID, "MODEL_VERIFIER_MISSING")
		if o.PVC == "" || o.StorageBytes <= 0 || o.MountPath == "" {
			block("SEED_PROFILE_UNSUPPORTED", "seed needs a distinct named PVC, explicit positive capacity and mount: "+o.ID)
		}
		if seeds[o.PVC] {
			block("SEED_PVC_REUSED", "each selected seed requires its own revision PVC: "+o.PVC)
		}
		seeds[o.PVC] = true
		if o.ModelSubPath != "" && (o.ModelSubPath == "." || !spec.SafePath(o.ModelSubPath)) {
			block("MODEL_SUBPATH_UNSUPPORTED", "model subdirectory must remain confined within its revision PVC: "+o.ID)
		}
		asset, err := v.Asset(o.Asset)
		if err != nil || asset.Type == "image" || len(asset.Files) == 0 {
			block("MODEL_MANIFEST_MISSING", "seed needs a locked non-image artifact with a signed file manifest: "+o.ID)
			continue
		}
		if _, err := modelstage.Manifest(asset.Files); err != nil {
			block("MODEL_MANIFEST_UNSUPPORTED", "model manifest is outside the supported verification profile: "+o.ID)
		}
		remaining := o.StorageBytes
		for _, file := range asset.Files {
			if file.Size < 0 || file.Size > remaining {
				block("MODEL_CAPACITY_INSUFFICIENT", "seed capacity is below its signed regular-file bytes: "+o.ID)
				break
			}
			remaining -= file.Size
		}
	}
	for _, c := range p.Checks {
		ref := c.Image
		if ref == "" {
			ref = e.Site.Spec.HelperImage
		}
		checkImage(ref, c.ID, "CHECK_IMAGE_MISSING")
		checkSecrets(c.SecretRefs, "check/"+c.ID)
		if c.ExpectedExitCode != 0 {
			block("CHECK_EXIT_UNSUPPORTED", "selected check requires unsupported nonzero expected exit code: "+c.ID)
		}
		if c.TimeoutSeconds < 0 || c.TimeoutSeconds > 86400 {
			block("CHECK_TIMEOUT_UNSUPPORTED", "selected check timeout exceeds the supported profile: "+c.ID)
		}
		switch c.Type {
		case "job":
			if len(c.Command) == 0 || c.Command[0] == "" {
				block("CHECK_COMMAND_MISSING", "selected Job check needs an explicit entrypoint: "+c.ID)
			}
		case "http":
			if c.Method != "" && c.Method != "GET" && c.Method != "HEAD" {
				block("HTTP_METHOD_UNSUPPORTED", "state-changing HTTP checks require an explicitly staged Job recipe: "+c.ID)
			}
			u, err := url.Parse(c.URL)
			if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
				block("HTTP_URL_UNSUPPORTED", "selected HTTP check URL is outside the supported profile: "+c.ID)
			} else if !slices.Contains(e.Site.Spec.AllowedHosts, u.Hostname()) {
				block("HTTP_HOST_NOT_ALLOWED", "selected HTTP check destination is not in the customer host allowlist: "+c.ID)
			}
			if c.ExpectedStatus < 100 || c.ExpectedStatus > 599 {
				block("HTTP_STATUS_UNSUPPORTED", "selected HTTP check needs an explicit valid expected status: "+c.ID)
			}
		default:
			block("CHECK_TYPE_UNSUPPORTED", "selected check is outside the supported execution profile: "+c.ID)
		}
	}
	return append(findings, e.fixtureFindings(ctx, p, v)...)
}

func (e *Engine) addExecutionFindings(ctx context.Context, p *spec.Plan, v *bundle.Verified, policy spec.TrustPolicy) {
	findings := e.ExecutionFindings(ctx, *p, v)
	for _, o := range p.Operations {
		if !slices.Contains(e.Site.Spec.AllowedActions, o.Type) || !slices.Contains(policy.Spec.AllowedActions, o.Type) {
			findings = append(findings, spec.Finding{Code: "CAPABILITY_DENIED", Severity: "blocker", Message: "selected operation is not permitted by both site and policy: " + o.Type})
		}
		if o.Type == "import" && e.Site.Spec.RegistryPlainHTTP && (!slices.Contains(e.Site.Spec.AllowedActions, "registry-http") || !slices.Contains(policy.Spec.AllowedActions, "registry-http")) {
			findings = append(findings, spec.Finding{Code: "REGISTRY_HTTP_DENIED", Severity: "blocker", Message: "plain HTTP registry needs explicit site and policy capability registry-http"})
		}
	}
	if len(p.Checks) > 0 && (!slices.Contains(e.Site.Spec.AllowedActions, "job") || !slices.Contains(policy.Spec.AllowedActions, "job")) {
		findings = append(findings, spec.Finding{Code: "CHECK_CAPABILITY_DENIED", Severity: "blocker", Message: "selected acceptance checks require site and policy Job capability"})
	}
	p.Findings = append(p.Findings, findings...)
	for _, finding := range findings {
		if finding.Severity == "blocker" {
			p.Executable = false
		}
	}
}

func importTargets(v *bundle.Verified, id string) ([]spec.LockedAsset, error) {
	targets := []spec.LockedAsset{}
	for _, asset := range v.Index.Lock.Assets {
		if id != "" && asset.ID != id {
			continue
		}
		if asset.Type != "image" {
			if id != "" {
				return nil, spec.Err(10, "selected import asset is not a locked image")
			}
			continue
		}
		if !spec.ValidDigest(asset.Digest) {
			return nil, spec.Err(12, "locked image import digest is invalid")
		}
		targets = append(targets, asset)
	}
	if len(targets) == 0 {
		return nil, spec.Err(10, "selected import has no matching locked image targets")
	}
	return targets, nil
}

func (e *Engine) checkExecutionProfile(ctx context.Context, p spec.Plan, v *bundle.Verified, policy spec.TrustPolicy) error {
	checked := p
	e.addExecutionFindings(ctx, &checked, v, policy)
	for _, finding := range checked.Findings {
		if finding.Severity == "blocker" {
			code := 10
			if finding.Code == "CAPABILITY_DENIED" || finding.Code == "CHECK_CAPABILITY_DENIED" || finding.Code == "REGISTRY_HTTP_DENIED" {
				code = 16
			}
			return spec.Err(code, "%s: %s", finding.Code, finding.Message)
		}
	}
	return nil
}
