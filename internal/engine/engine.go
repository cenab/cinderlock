package engine

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Engine struct {
	Site          spec.Site
	Store         *state.Store
	Kube          *Kubernetes
	StateDir      string
	HelmRunner    func(context.Context, ...string) ([]byte, error)
	PodLogReader  func(context.Context, string) ([]byte, error)
	ModelAttach   func(context.Context, string, io.Reader, io.Writer, io.Writer) error
	DynamicClient dynamic.Interface
}

func New(site spec.Site, store *state.Store) (*Engine, error) {
	k, err := NewKubernetes(site.Spec.Kubeconfig, site.Spec.Context, site.Spec.Namespace, site.Spec.ReleaseName)
	if err != nil {
		return nil, err
	}
	e := NewWithClient(site, store, k.Client)
	e.Kube = k
	if err := os.MkdirAll(e.StateDir, 0700); err != nil {
		return nil, err
	}
	return e, nil
}

func NewWithClient(site spec.Site, store *state.Store, client kubernetes.Interface) *Engine {
	dir := site.Spec.StateDir
	if dir == "" {
		base, _ := os.UserCacheDir()
		dir = filepath.Join(base, "cinderlock")
	}
	return &Engine{Site: site, Store: store, StateDir: dir, Kube: &Kubernetes{Client: client, Config: &rest.Config{Host: "https://test.invalid"}, Namespace: site.Spec.Namespace, Release: site.Spec.ReleaseName, Kubeconfig: site.Spec.Kubeconfig, Context: site.Spec.Context}}
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func (e *Engine) Inspect(ctx context.Context) (spec.TargetSnapshot, error) {
	o, err := e.Kube.Observe(ctx)
	if err != nil {
		return spec.TargetSnapshot{}, err
	}
	s := spec.TargetSnapshot{Header: spec.NewHeader("TargetSnapshot"), SiteID: e.Site.Metadata.Name, TargetID: o.TargetID, NamespaceUID: o.NamespaceUID, ObservedAt: spec.Now(), DataRevision: e.Site.Spec.DataRevision, Resources: []spec.ResourceFact{}, Facts: []spec.Fact{}, Findings: []spec.Finding{}}
	if e.Site.Spec.NamespaceUID != "" && e.Site.Spec.NamespaceUID != o.NamespaceUID {
		return s, spec.Err(11, "namespace UID differs from site pin")
	}
	if e.Site.Spec.ClusterID != "" && e.Site.Spec.ClusterID != o.TargetID {
		return s, spec.Err(11, "target identity differs from site pin")
	}
	for _, r := range o.Resources {
		s.Resources = append(s.Resources, spec.ResourceFact{Kind: r.Kind, Name: r.Name, Namespace: e.Site.Spec.Namespace, UID: r.UID, Fingerprint: r.Fingerprint})
		s.Facts = append(s.Facts, spec.Fact{Name: "readiness/" + r.Kind + "/" + r.Name, Value: fmt.Sprint(r.Ready), Status: "known", Source: "Kubernetes resource status"})
	}
	sort.Slice(s.Resources, func(i, j int) bool {
		return s.Resources[i].Kind+"/"+s.Resources[i].Name < s.Resources[j].Kind+"/"+s.Resources[j].Name
	})
	s.Facts = append(s.Facts, spec.Fact{Name: "kubernetes.version", Value: o.KubernetesVersion, Status: "known", Source: "Kubernetes discovery"})
	gp, err := e.Kube.ObserveGPUs(ctx)
	if err != nil {
		s.Facts = append(s.Facts, spec.Fact{Name: "nvidia.allocatable", Status: "unavailable", Source: "node authorization/discovery"})
	} else {
		var total int64
		for _, count := range gp {
			var n int64
			_, _ = fmt.Sscan(count, &n)
			total += n
		}
		s.Facts = append(s.Facts, spec.Fact{Name: "nvidia.allocatable", Value: fmt.Sprint(total), Status: "known", Source: "Kubernetes node allocatable; not hardware qualification"})
	}
	for name, ref := range e.Site.Spec.SecretRefs {
		if ref.File != "" {
			info, err := os.Lstat(ref.File)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				s.Facts = append(s.Facts, spec.Fact{Name: "secret/" + name, Status: "unavailable", Source: "local private-file reference"})
				continue
			}
			s.Facts = append(s.Facts, spec.Fact{Name: "secret/" + name, Value: fmt.Sprintf("%d/%d", info.Size(), info.ModTime().UnixNano()), Status: "known", Source: "local file metadata only"})
			continue
		}
		ns := ref.Namespace
		if ns == "" {
			ns = e.Site.Spec.Namespace
		}
		if ns != e.Site.Spec.Namespace {
			return s, spec.Err(16, "cross-namespace secret reference is unsupported")
		}
		secret, err := e.Kube.Client.CoreV1().Secrets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			s.Facts = append(s.Facts, spec.Fact{Name: "secret/" + name, Status: "unavailable", Source: "Kubernetes metadata access"})
			continue
		}
		if ref.Key != "" {
			if _, ok := secret.Data[ref.Key]; !ok {
				s.Facts = append(s.Facts, spec.Fact{Name: "secret/" + name, Status: "unavailable", Source: "referenced Kubernetes Secret key is absent"})
				continue
			}
		}
		s.Facts = append(s.Facts, spec.Fact{Name: "secret/" + name, Value: string(secret.UID) + "/" + secret.ResourceVersion, Status: "known", Source: "Kubernetes UID/resourceVersion, not value"})
	}
	for _, name := range e.Site.Spec.ImagePullSecrets {
		secret, err := e.Kube.Client.CoreV1().Secrets(e.Site.Spec.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			s.Facts = append(s.Facts, spec.Fact{Name: "secret/image-pull-" + name, Status: "unavailable", Source: "Kubernetes Secret metadata access"})
			continue
		}
		s.Facts = append(s.Facts, spec.Fact{Name: "secret/image-pull-" + name, Value: string(secret.UID) + "/" + secret.ResourceVersion, Status: "known", Source: "Kubernetes UID/resourceVersion only"})
	}
	sort.Slice(s.Facts, func(i, j int) bool { return s.Facts[i].Name < s.Facts[j].Name })
	rev, version, values, err := e.helmState(ctx)
	if err != nil {
		return s, err
	}
	s.HelmRevision = rev
	s.InstalledVersion = version
	configDigest, err := e.privateFingerprint(values)
	if err != nil {
		return s, err
	}
	s.EffectiveConfigDigest = configDigest
	if s.DataRevision != "" {
		s.Facts = append(s.Facts, spec.Fact{Name: "application.dataRevision", Value: s.DataRevision, Status: "asserted", Source: "customer Site assertion; vendor operation must enforce its own schema precondition"})
	}
	return s, nil
}

func (e *Engine) privateFingerprint(data []byte) (string, error) {
	if err := os.MkdirAll(e.StateDir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(e.StateDir, "configuration-fingerprint.key")
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return "", err
		}
		if err := spec.WriteBytes(path, key); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return "", err
			}
			key, err = os.ReadFile(path)
			if err != nil {
				return "", err
			}
		}
	} else if err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", errors.New("invalid local fingerprint key")
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return "hmac-sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func snapshotDigest(s spec.TargetSnapshot) (string, error) {
	s.ObservedAt = ""
	s.Findings = nil
	facts := []spec.Fact{}
	for _, f := range s.Facts {
		if !strings.HasPrefix(f.Name, "readiness/") {
			facts = append(facts, f)
		}
	}
	s.Facts = facts
	return spec.Digest(s)
}

func (e *Engine) Plan(ctx context.Context, v *bundle.Verified, bundlePath, sitePath string, policy spec.TrustPolicy) (spec.Plan, error) {
	if err := spec.ValidateRelease(v.Index.Lock.Release); err != nil {
		return spec.Plan{}, err
	}
	snap, err := e.Inspect(ctx)
	if err != nil {
		return spec.Plan{}, err
	}
	r := v.Index.Lock.Release
	p := spec.Plan{Header: spec.NewHeader("Plan"), BundlePath: bundlePath, BundleDigest: v.Digest, SitePath: sitePath, Snapshot: snap, SourceVersion: snap.InstalledVersion, TargetVersion: r.Metadata.Version, Checks: r.Spec.Checks, RequiredChecks: r.Spec.RequiredChecks, Recovery: r.Spec.Recovery, Findings: []spec.Finding{}, CreatedAt: spec.Now(), Executable: true, PolicyEpoch: policy.Spec.Epoch}
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
	p.SnapshotDigest, err = snapshotDigest(snap)
	if err != nil {
		return p, err
	}
	block := func(code, message string) {
		p.Findings = append(p.Findings, spec.Finding{Code: code, Severity: "blocker", Message: message})
		p.Executable = false
	}
	e.addPolicyFloorFindings(ctx, &p)
	if e.Site.Spec.Profile != r.Spec.Profile {
		block("PROFILE_MISMATCH", "site profile does not match release profile")
	}
	if r.Spec.Deployment.Type == "gitops" {
		block("GITOPS_EXTERNAL_OWNER", "GitOps release must be delivered through its declared desired-state owner; direct apply is refused")
	}
	if r.Spec.Deployment.Type != "helm" && r.Spec.Deployment.Type != "gitops" {
		block("UNSUPPORTED_DEPLOYMENT", "only Helm deployment has a mutating adapter")
	}
	if policy.Spec.ExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, policy.Spec.ExpiresAt)
		if err != nil || !time.Now().Before(expiry) {
			block("POLICY_EXPIRED", "trust policy has expired")
		}
	}
	var transition *spec.Transition
	for i := range r.Spec.Transitions {
		t := &r.Spec.Transitions[i]
		if t.FromRelease == snap.InstalledVersion || (snap.InstalledVersion == "" && t.FromRelease == "install") {
			if transition != nil {
				block("AMBIGUOUS_TRANSITION", "multiple transitions match starting version")
			}
			transition = t
		}
	}
	if transition == nil {
		block("UNSUPPORTED_TRANSITION", "no declared transition matches the observed source version")
	} else {
		p.TransitionID = transition.ID
		if transition.FromDataRevision != "" && transition.FromDataRevision != e.Site.Spec.DataRevision {
			block("DATA_REVISION_MISMATCH", "source data revision does not match the declared transition")
		}
		if transition.FromEmbeddingRevision != "" && e.Site.Spec.EmbeddingRevision != transition.FromEmbeddingRevision {
			block("EMBEDDING_REVISION_MISMATCH", "source embedding profile does not match transition")
		}
		if e.Site.Spec.EmbeddingRevision != "" && r.Spec.AIProfile.EmbeddingRevision != "" && e.Site.Spec.EmbeddingRevision != r.Spec.AIProfile.EmbeddingRevision && transition.ReindexOperation == "" {
			block("REINDEX_REQUIRED", "changed embedding profile has no supported reindex operation")
		}
		byID := map[string]spec.Operation{}
		for _, o := range r.Spec.Operations {
			byID[o.ID] = o
		}
		for _, id := range transition.Operations {
			o, ok := byID[id]
			if !ok {
				block("OPERATION_MISSING", "transition refers to undefined operation "+id)
				continue
			}
			p.Operations = append(p.Operations, o)
		}
		if transition.Recovery != "" {
			found := false
			for _, recovery := range p.Recovery {
				if recovery.ID == transition.Recovery {
					found = true
				}
			}
			if !found {
				block("RECOVERY_MISSING", "transition recovery procedure is undefined")
			}
		}
	}
	if len(p.Operations) == 0 {
		block("NO_OPERATIONS", "transition contains no executable operations")
	}
	if e.Site.Spec.StorageProfile == "" && (e.Site.Spec.CapacityBytes <= 0 || e.Site.Spec.CapacityBytes < r.Spec.MinFreeBytes) {
		block("CAPACITY_UNVERIFIED", "customer-declared capacity is missing or below the release minimum")
	}
	if r.Spec.AIProfile.GPUCount > 0 {
		found := false
		for _, f := range snap.Facts {
			if f.Name == "nvidia.allocatable" && f.Status == "known" {
				found = true
				var n int64
				_, _ = fmt.Sscan(f.Value, &n)
				if n < r.Spec.AIProfile.GPUCount {
					block("GPU_UNAVAILABLE", "insufficient advertised NVIDIA GPU resources")
				}
			}
		}
		if !found {
			block("GPU_UNVERIFIED", "GPU allocation facts unavailable")
		}
	}
	if r.Spec.AIProfile.GPUCount > 0 || len(r.Spec.AIProfile.GPUModels) > 0 || r.Spec.AIProfile.MinGPUMemoryMiB > 0 || len(r.Spec.AIProfile.DriverVersions) > 0 {
		if err := e.validateConfiguredHardware(ctx, v); err != nil {
			block("GPU_PROFILE_UNQUALIFIED", err.Error())
		}
	}
	if req := r.Spec.License; req != nil {
		if req.Mode != "offline" {
			block("ONLINE_LICENSE_UNSUPPORTED", "application license mode is not declared offline")
		}
		if _, ok := e.Site.Spec.SecretRefs[req.SecretRef]; !ok {
			block("LICENSE_MISSING", "offline license reference is missing")
		}
		if req.ExpiresAt != "" {
			expiry, err := time.Parse(time.RFC3339, req.ExpiresAt)
			if err != nil || !time.Now().Before(expiry) {
				block("LICENSE_EXPIRED", "declared offline license validity is expired or invalid")
			}
		}
	}
	for _, o := range p.Operations {
		if !slices.Contains(e.Site.Spec.AllowedActions, o.Type) || !slices.Contains(policy.Spec.AllowedActions, o.Type) {
			block("CAPABILITY_DENIED", "operation type not permitted by both site and policy: "+o.Type)
		}
		if (o.Type == "migrate" || o.Type == "reindex") && !o.Idempotent && len(o.ReconcileCommand) == 0 {
			block("RECONCILIATION_MISSING", "non-idempotent operation lacks reconciliation command: "+o.ID)
		}
		for _, ref := range o.SecretRefs {
			if _, ok := e.Site.Spec.SecretRefs[ref]; !ok {
				block("SECRET_MISSING", "operation secret reference missing: "+ref)
			}
		}
	}
	checks := map[string]spec.Check{}
	for _, c := range p.Checks {
		checks[c.ID] = c
	}
	for _, id := range p.RequiredChecks {
		if _, ok := checks[id]; !ok {
			block("REQUIRED_CHECK_MISSING", "required check undefined: "+id)
		}
	}
	if len(p.RequiredChecks) == 0 {
		block("ACCEPTANCE_UNDEFINED", "release defines no required application acceptance checks")
	}
	if transition != nil {
		for _, rec := range r.Spec.Recovery {
			if rec.ID != transition.Recovery || !rec.RequiresBackup {
				continue
			}
			backup := false
			for _, op := range p.Operations {
				if op.Type == "backup" {
					backup = true
				}
				if op.Type == "migrate" || op.Type == "reindex" || op.Type == "helm" {
					break
				}
			}
			if e.Site.Spec.BackupRef == "" || !backup {
				block("BACKUP_PREREQUISITE_MISSING", "recovery requires a declared backup reference and a verifying backup Job before the first data/deployment mutation")
			}
		}
	}
	available := map[string]bool{}
	for _, fact := range snap.Facts {
		if fact.Status == "known" {
			available[fact.Name] = true
		}
	}
	requiredRefs := []string{}
	for _, op := range p.Operations {
		requiredRefs = append(requiredRefs, op.SecretRefs...)
	}
	for _, c := range p.Checks {
		requiredRefs = append(requiredRefs, c.SecretRefs...)
	}
	if r.Spec.License != nil {
		requiredRefs = append(requiredRefs, r.Spec.License.SecretRef)
	}
	if p.Kind != "RetirementPlan" && e.Site.Spec.RegistryAuthRef != "" {
		requiredRefs = append(requiredRefs, e.Site.Spec.RegistryAuthRef)
	}
	for _, ref := range requiredRefs {
		if !available["secret/"+ref] {
			block("SECRET_UNAVAILABLE", "required secret reference is absent, denied, or unreadable: "+ref)
		}
	}
	for _, name := range e.Site.Spec.ImagePullSecrets {
		if !available["secret/image-pull-"+name] {
			block("IMAGE_PULL_SECRET_UNAVAILABLE", "image pull Secret is absent, denied, or unreadable: "+name)
		}
	}
	if e.Store != nil {
		floor, err := e.Store.ReleaseFloor(ctx, snap.TargetID, r.Metadata.Application, r.Metadata.Channel)
		if err != nil {
			return p, err
		}
		if r.Metadata.Sequence < floor {
			block("RELEASE_REPLAY", "release sequence is lower than the locally accepted high-water sequence")
		}
	}
	e.addExecutionFindings(ctx, &p, v, policy)
	e.addStorageFindings(ctx, &p, v, policy)
	e.addConfigurationFindings(ctx, &p, v)
	var objects []map[string]any
	if p.Executable {
		objects, err = e.render(ctx, v)
		if err != nil {
			block("CHART_UNSUPPORTED", err.Error())
		} else if p.DesiredStateDigest, err = spec.Digest(objects); err != nil {
			return p, err
		}
	}
	e.addPermissionFindings(ctx, &p, objects)
	e.addAdmissionFindings(ctx, &p, objects, policy)
	return p, nil
}

func (e *Engine) checkPlan(ctx context.Context, p spec.Plan, v *bundle.Verified, policy spec.TrustPolicy, initial bool) error {
	if err := e.verifyRecipeBinding(p, v); err != nil {
		return err
	}
	if err := e.checkConfigurationPlan(ctx, p, v); err != nil {
		return err
	}
	if !p.Executable {
		return spec.Err(10, "plan has blocking findings")
	}
	if p.BundleDigest != v.Digest {
		return spec.Err(12, "plan bundle digest differs from verified bundle")
	}
	embedded, err := snapshotDigest(p.Snapshot)
	if err != nil || embedded != p.SnapshotDigest || p.SourceVersion != p.Snapshot.InstalledVersion {
		return spec.Err(11, "plan starting state or source version differs from its bound snapshot")
	}
	currentSource, err := sourceSiteDigest(p.SitePath)
	if err != nil {
		return err
	}
	if p.SourceSiteDigest == "" || currentSource != p.SourceSiteDigest {
		return spec.Err(11, "source Site file changed after planning")
	}
	var admitted spec.TrustPolicy
	if err := spec.Read(e.Site.Spec.TrustPolicy, &admitted); err != nil {
		return spec.Err(16, "current trust policy cannot be reread: %v", err)
	}
	admittedDigest, err := spec.Digest(admitted)
	if err != nil {
		return err
	}
	if admittedDigest != p.PolicyDigest || admitted.Spec.Epoch != p.PolicyEpoch {
		return spec.Err(11, "current trust policy changed; stop at safe boundary and create a new authorized plan")
	}
	siteDigest, err := spec.Digest(e.Site)
	if err != nil {
		return err
	}
	policyDigest, err := spec.Digest(policy)
	if err != nil {
		return err
	}
	if siteDigest != p.SiteDigest || policyDigest != p.PolicyDigest || policy.Spec.Epoch != p.PolicyEpoch {
		return spec.Err(11, "site or trust policy changed after planning")
	}
	if expiry := policy.Spec.ExpiresAt; expiry != "" {
		t, err := time.Parse(time.RFC3339, expiry)
		if err != nil || !time.Now().Before(t) {
			return spec.Err(16, "trust policy expired")
		}
	}
	current, err := e.Inspect(ctx)
	if err != nil {
		return err
	}
	if current.TargetID != p.Snapshot.TargetID || current.NamespaceUID != p.Snapshot.NamespaceUID {
		return spec.Err(11, "target identity changed")
	}
	if err := e.checkPolicyFloor(ctx, p); err != nil {
		return err
	}
	if err := e.checkExecutionProfile(ctx, p, v, policy); err != nil {
		return err
	}
	if err := e.checkStoragePlan(ctx, p, v, policy, initial); err != nil {
		return err
	}
	available := map[string]bool{}
	for _, fact := range current.Facts {
		if fact.Status == "known" {
			available[fact.Name] = true
		}
	}
	required := []string{}
	for _, op := range p.Operations {
		required = append(required, op.SecretRefs...)
	}
	for _, check := range p.Checks {
		required = append(required, check.SecretRefs...)
	}
	if p.Kind != "RetirementPlan" && v.Index.Lock.Release.Spec.License != nil {
		required = append(required, v.Index.Lock.Release.Spec.License.SecretRef)
	}
	if p.Kind != "RetirementPlan" && e.Site.Spec.RegistryAuthRef != "" {
		required = append(required, e.Site.Spec.RegistryAuthRef)
	}
	for _, ref := range required {
		if !available["secret/"+ref] {
			return spec.Err(10, "required secret reference became unavailable: %s", ref)
		}
	}
	if p.Kind != "ProbePlan" && p.Kind != "RetirementPlan" {
		profile := v.Index.Lock.Release.Spec.AIProfile
		if profile.GPUCount > 0 || len(profile.GPUModels) > 0 || profile.MinGPUMemoryMiB > 0 || len(profile.DriverVersions) > 0 {
			if err := e.validateConfiguredHardware(ctx, v); err != nil {
				return err
			}
		}
	}
	if initial {
		digest, err := snapshotDigest(current)
		if err != nil {
			return err
		}
		if digest != p.SnapshotDigest {
			return spec.Err(11, "target state changed after planning")
		}
		if p.Kind == "Plan" {
			fresh, err := e.Plan(ctx, v, p.BundlePath, p.SitePath, policy)
			if err != nil {
				return err
			}
			if !fresh.Executable {
				return spec.Err(10, "required release prerequisites are no longer executable")
			}
			if fresh.SourceVersion != p.SourceVersion || fresh.TargetVersion != p.TargetVersion || fresh.TransitionID != p.TransitionID || fresh.Destructive != p.Destructive || fresh.DesiredStateDigest != p.DesiredStateDigest {
				return spec.Err(11, "submitted transition differs from the transition derived from actual target state")
			}
		}
	}
	return nil
}

func sourceSiteDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", spec.Err(11, "source Site file unavailable: %v", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > spec.MaxDocumentBytes {
		return "", spec.Err(2, "source Site file must be a bounded regular file")
	}
	body, err := io.ReadAll(io.LimitReader(f, spec.MaxDocumentBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > spec.MaxDocumentBytes {
		return "", spec.Err(2, "source Site file exceeds size limit")
	}
	return spec.Hash(body), nil
}

func (e *Engine) verifyRecipeBinding(p spec.Plan, v *bundle.Verified) error {
	if err := spec.ValidateHeader(p.Header, p.Kind); err != nil {
		return err
	}
	r := v.Index.Lock.Release
	if err := spec.ValidateRelease(r); err != nil {
		return err
	}
	if p.Metadata.Application != r.Metadata.Application || p.Metadata.Channel != r.Metadata.Channel || p.Metadata.Sequence != r.Metadata.Sequence || p.SitePath == "" || p.BundlePath == "" {
		return spec.Err(12, "plan identity is not bound to the signed release")
	}
	if p.Kind != "RecoveryPlan" && p.SourceRun != "" {
		return spec.Err(12, "only a separately validated recovery plan can supersede a prior run")
	}
	equal := func(a, b any) bool {
		da, ea := spec.Digest(struct {
			Value any `json:"value"`
		}{a})
		db, eb := spec.Digest(struct {
			Value any `json:"value"`
		}{b})
		return ea == nil && eb == nil && da == db
	}
	if !equal(p.Recovery, r.Spec.Recovery) {
		return spec.Err(12, "plan recovery definitions differ from the signed release")
	}
	if p.Kind == "ProbePlan" {
		return e.verifyProbeBinding(p, v)
	}
	if p.Kind == "RetirementPlan" {
		if p.TransitionID != "retain-data-uninstall" || p.TargetVersion != "" || len(p.Operations) != 1 || len(p.Checks) != 0 || len(p.RequiredChecks) != 0 {
			return spec.Err(12, "retirement scope differs from fixed retention contract")
		}
		operation := p.Operations[0]
		if operation.ID != "uninstall" || operation.Type != "uninstall" || len(operation.Command) != 0 || len(operation.Args) != 0 || operation.Image != "" || operation.PVC != "" || operation.TimeoutSeconds != 300 {
			return spec.Err(12, "modified retirement operation rejected")
		}
		return nil
	}
	if p.Kind == "RecoveryPlan" {
		if len(p.Operations) == 0 || len(p.RequiredChecks) == 0 {
			return spec.Err(10, "manual-only or incomplete recovery cannot execute as accepted recovery")
		}
		for _, recovery := range r.Spec.Recovery {
			if recovery.ToRelease == p.TargetVersion && recovery.Destructive == p.Destructive && equal(recovery.Operations, p.Operations) && equal(recovery.Checks, p.Checks) {
				workflow := false
				for _, check := range recovery.Checks {
					if check.Required && check.Domain == "workflow" {
						workflow = true
					}
				}
				if !workflow {
					return spec.Err(10, "recovery requires an explicit required application workflow")
				}
				if recovery.RequiresBackup && e.Site.Spec.BackupRef == "" {
					return spec.Err(10, "recovery backup reference is missing")
				}
				if recovery.DataRevision != "" && recovery.DataRevision != e.Site.Spec.DataRevision {
					return spec.Err(10, "recovery data revision differs from its declared precondition")
				}
				required := []string{}
				for _, c := range recovery.Checks {
					if c.Required {
						required = append(required, c.ID)
					}
				}
				if equal(required, p.RequiredChecks) {
					return nil
				}
			}
		}
		return spec.Err(12, "recovery plan scope is not a signed recovery recipe")
	}
	if p.Kind != "Plan" || p.TargetVersion != r.Metadata.Version || !equal(p.Checks, r.Spec.Checks) || !equal(p.RequiredChecks, r.Spec.RequiredChecks) {
		return spec.Err(12, "plan checks/version differ from signed release")
	}
	byID := map[string]spec.Operation{}
	for _, o := range r.Spec.Operations {
		byID[o.ID] = o
	}
	for _, t := range r.Spec.Transitions {
		if t.ID != p.TransitionID {
			continue
		}
		if t.FromRelease != p.SourceVersion && !(p.SourceVersion == "" && t.FromRelease == "install") {
			continue
		}
		expected := []spec.Operation{}
		for _, id := range t.Operations {
			op, ok := byID[id]
			if !ok {
				return spec.Err(12, "signed transition operation missing")
			}
			expected = append(expected, op)
		}
		if equal(expected, p.Operations) {
			return nil
		}
	}
	return spec.Err(12, "plan operations differ from signed transition")
}

func (e *Engine) currentCheckpoint(ctx context.Context, runID string, p spec.Plan) (spec.TargetSnapshot, error) {
	digest, body, err := e.Store.Checkpoint(ctx, runID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			digest = p.SnapshotDigest
			body, err = spec.Canonical(p.Snapshot)
			if err != nil {
				return spec.TargetSnapshot{}, err
			}
		} else {
			return spec.TargetSnapshot{}, err
		}
	}
	current, err := e.Inspect(ctx)
	if err != nil {
		return current, err
	}
	actual, err := snapshotDigest(current)
	if err != nil {
		return current, err
	}
	if actual != digest {
		return current, spec.Err(11, "target configuration or secret binding changed since the last confirmed checkpoint")
	}
	var expected spec.TargetSnapshot
	if err := spec.Decode(body, &expected); err != nil {
		return current, err
	}
	return expected, nil
}

func (e *Engine) advanceCheckpoint(ctx context.Context, runID string, op spec.Operation, before spec.TargetSnapshot) (spec.TargetSnapshot, error) {
	after, err := e.Inspect(ctx)
	if err != nil {
		return after, err
	}
	secrets := func(snapshot spec.TargetSnapshot) []spec.Fact {
		facts := []spec.Fact{}
		for _, f := range snapshot.Facts {
			if strings.HasPrefix(f.Name, "secret/") {
				facts = append(facts, f)
			}
		}
		return facts
	}
	a, _ := spec.Digest(secrets(before))
	b, _ := spec.Digest(secrets(after))
	if a != b {
		return after, spec.Err(11, "secret binding changed while operation was running")
	}
	if op.Type != "helm" && op.Type != "restart" && op.Type != "uninstall" {
		a, _ := snapshotDigest(before)
		b, _ := snapshotDigest(after)
		if a != b {
			return after, spec.Err(11, "unexpected Kubernetes/configuration drift during non-resource operation")
		}
	}
	digest, err := snapshotDigest(after)
	if err != nil {
		return after, err
	}
	if err := e.Store.SetCheckpoint(ctx, runID, digest, after); err != nil {
		return after, err
	}
	return after, nil
}

func (e *Engine) image(v *bundle.Verified, ref string) (string, error) {
	if ref == "" {
		return "", spec.Err(10, "an explicit locked image reference is required")
	}
	for _, a := range v.Index.Lock.Assets {
		if a.Type != "image" {
			continue
		}
		if ref == a.ID || ref == a.Source || ref == a.Digest {
			if !spec.ValidDigest(a.Digest) {
				return "", spec.Err(12, "locked image digest is invalid")
			}
			if e.Site.Spec.Registry == "" {
				return "", spec.Err(10, "site internal registry is required")
			}
			return strings.TrimSuffix(e.Site.Spec.Registry, "/") + "/" + strings.ToLower(a.ID) + "@" + a.Digest, nil
		}
	}
	return "", spec.Err(10, "image is not a locked declared image asset: %s", ref)
}
