package engine

import (
	"bytes"
	"context"
	"slices"
	"strings"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"oras.land/oras-go/v2/registry"
)

func artifactOperations(v *bundle.Verified) ([]spec.Operation, error) {
	r := v.Index.Lock.Release
	if err := spec.ValidateRelease(r); err != nil {
		return nil, err
	}
	if r.Spec.Deployment.Type != "gitops" || r.Spec.Deployment.GitOps == nil || !slices.Contains([]string{"flux", "argocd"}, r.Spec.Deployment.GitOps.Owner) {
		return nil, spec.Err(10, "artifact staging requires a declared supported GitOps owner")
	}
	assets, err := importTargets(v, "")
	if err != nil {
		return nil, err
	}
	if len(assets) > 128 {
		return nil, spec.Err(10, "image staging exceeds the bounded journal profile")
	}
	seen := map[string]bool{}
	ops := make([]spec.Operation, 0, len(assets))
	for _, asset := range assets {
		op := spec.Operation{ID: asset.ID, Type: "import", Asset: asset.ID, Idempotent: true}
		if err := spec.ValidateOperation(op); err != nil || seen[asset.ID] || asset.RootDescriptor == nil || asset.RootDescriptor.Digest != asset.Digest || asset.RootDescriptor.Size <= 0 {
			return nil, spec.Err(12, "artifact staging requires unique exact image descriptor identities")
		}
		seen[asset.ID] = true
		ops = append(ops, op)
	}
	return ops, nil
}

// ArtifactsPlan stages signed image graphs only. Controller reconciliation,
// application workflows, model volumes, and data recovery remain separate.
func (e *Engine) ArtifactsPlan(ctx context.Context, v *bundle.Verified, bundlePath, sitePath string, policy spec.TrustPolicy) (spec.Plan, error) {
	if err := spec.ValidatePolicy(policy); err != nil {
		return spec.Plan{}, err
	}
	ops, err := artifactOperations(v)
	if err != nil {
		return spec.Plan{}, err
	}
	if !slices.Contains(e.Site.Spec.AllowedActions, "gitops-stage") || !slices.Contains(policy.Spec.AllowedActions, "gitops-stage") {
		return spec.Plan{}, spec.Err(16, "GitOps image staging requires site and policy gitops-stage capability")
	}
	for _, op := range ops {
		ref, err := registry.ParseReference(strings.TrimSuffix(e.Site.Spec.Registry, "/") + "/" + op.Asset)
		if err != nil || ref.Reference != "" {
			return spec.Plan{}, spec.Err(10, "GitOps staging requires an untagged explicit registry repository destination")
		}
	}
	snapshot, err := e.inspectArtifacts(ctx)
	if err != nil {
		return spec.Plan{}, err
	}
	r := v.Index.Lock.Release
	p := spec.Plan{Header: spec.NewHeader("ArtifactsPlan"), BundlePath: bundlePath, BundleDigest: v.Digest, SitePath: sitePath, Snapshot: snapshot, TargetVersion: r.Metadata.Version, TransitionID: "gitops-image-staging", Operations: ops, Checks: []spec.Check{}, RequiredChecks: []string{}, Recovery: r.Spec.Recovery, CreatedAt: spec.Now(), Executable: true, PolicyEpoch: policy.Spec.Epoch, Findings: []spec.Finding{{Code: "GITOPS_IMAGE_STAGING_ONLY", Severity: "info", Message: "copies the selected signed image graphs to the declared registry; does not stage model/data volumes, validate operational entitlement, change desired state, reconcile a controller, or establish application acceptance"}}}
	p.Metadata = r.Metadata
	p.SourceSiteDigest, err = sourceSiteDigest(sitePath)
	if err != nil {
		return p, err
	}
	p.SiteDigest, err = spec.Digest(e.Site)
	if err != nil {
		return p, err
	}
	p.PolicyDigest, err = spec.Digest(policy)
	if err != nil {
		return p, err
	}
	p.SnapshotDigest, err = snapshotDigest(snapshot)
	if err != nil {
		return p, err
	}
	if e.Site.Spec.Profile != r.Spec.Profile {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "PROFILE_MISMATCH", Severity: "blocker", Message: "site profile does not match release profile"})
	}
	e.addPolicyFloorFindings(ctx, &p)
	e.addExecutionFindings(ctx, &p, v, policy)
	e.addStorageFindings(ctx, &p, v, policy)
	e.addPermissionFindings(ctx, &p, nil)
	return p, nil
}

func (e *Engine) verifyArtifactsBinding(p spec.Plan, v *bundle.Verified) error {
	expected, err := artifactOperations(v)
	if err != nil {
		return err
	}
	a, err := spec.Canonical(expected)
	if err != nil {
		return err
	}
	b, err := spec.Canonical(p.Operations)
	if err != nil || !bytes.Equal(a, b) || p.Metadata.Version != v.Index.Lock.Release.Metadata.Version || p.TargetVersion != v.Index.Lock.Release.Metadata.Version || p.SourceVersion != "" || p.TransitionID != "gitops-image-staging" || p.Destructive || len(p.Checks) != 0 || len(p.RequiredChecks) != 0 || len(p.RetainedResources) != 0 || p.ConfigurationReview != nil || p.DesiredStateDigest != "" {
		return spec.Err(12, "artifact staging differs from the fixed signed image-only scope")
	}
	return nil
}

func (e *Engine) inspectPlan(ctx context.Context, p spec.Plan) (spec.TargetSnapshot, error) {
	if p.Kind == "ArtifactsPlan" {
		return e.inspectArtifacts(ctx)
	}
	return e.Inspect(ctx)
}

func (e *Engine) inspectArtifacts(ctx context.Context) (spec.TargetSnapshot, error) {
	var s spec.TargetSnapshot
	if e.Kube == nil || e.Kube.Config == nil || e.Kube.Client == nil {
		return s, spec.Err(10, "artifact staging requires an explicit target")
	}
	ns, err := e.Kube.Client.CoreV1().Namespaces().Get(ctx, e.Site.Spec.Namespace, metav1.GetOptions{})
	if err != nil {
		return s, err
	}
	if ns.UID == "" || ns.DeletionTimestamp != nil {
		return s, spec.Err(10, "artifact staging namespace has no stable live identity")
	}
	id := TargetIdentity(e.Kube.Config.Host, string(ns.UID))
	if e.Site.Spec.NamespaceUID != "" && e.Site.Spec.NamespaceUID != string(ns.UID) || e.Site.Spec.ClusterID != "" && e.Site.Spec.ClusterID != id {
		return s, spec.Err(11, "artifact staging target identity differs from Site pins")
	}
	s = spec.TargetSnapshot{Header: spec.NewHeader("TargetSnapshot"), SiteID: e.Site.Metadata.Name, TargetID: id, NamespaceUID: string(ns.UID), ObservedAt: spec.Now(), Resources: []spec.ResourceFact{}, Facts: []spec.Fact{}, Findings: []spec.Finding{}}
	if name := e.Site.Spec.RegistryAuthRef; name != "" {
		ref, ok := e.Site.Spec.SecretRefs[name]
		if !ok {
			return s, spec.Err(10, "registry credential reference is missing")
		}
		value := ""
		if ref.File != "" {
			value, err = e.privateFileFingerprint(ref.File)
		} else {
			if ref.Namespace != "" && ref.Namespace != e.Site.Spec.Namespace {
				return s, spec.Err(16, "registry credential reference crosses the target namespace")
			}
			secret, readErr := e.Kube.Client.CoreV1().Secrets(e.Site.Spec.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
			if readErr != nil {
				return s, spec.Err(10, "registry credential Secret is unavailable")
			}
			key := ref.Key
			if key == "" {
				key = ".dockerconfigjson"
			}
			data := secret.Data[key]
			if secret.UID == "" || secret.DeletionTimestamp != nil || len(data) == 0 || len(data) > 1<<20 {
				return s, spec.Err(10, "registry credential key or stable Secret identity is unavailable")
			}
			value, err = e.secretFingerprint(secret, map[string][]byte{key: data})
		}
		if err != nil {
			return s, spec.Err(10, "registry credential binding is unavailable")
		}
		s.Facts = append(s.Facts, spec.Fact{Name: "secret/" + name, Value: value, Status: "known", Source: "registry-only private credential binding"})
	}
	if e.Site.Spec.RegistryCAFile != "" {
		data, err := readKubernetesInput(e.Site.Spec.RegistryCAFile, 1<<20)
		if err != nil {
			return s, spec.Err(10, "registry CA binding is unavailable")
		}
		value, err := e.privateFingerprint(append([]byte("cinderlock.gitops-registry-ca.v1\x00"), data...))
		if err != nil {
			return s, err
		}
		s.Facts = append(s.Facts, spec.Fact{Name: "registry.ca", Value: value, Status: "known", Source: "registry CA private binding"})
	}
	return s, nil
}
