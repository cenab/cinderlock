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
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	s := spec.TargetSnapshot{Header: spec.NewHeader("TargetSnapshot"), SiteID: e.Site.Metadata.Name, TargetID: o.TargetID, NamespaceUID: o.NamespaceUID, ObservedAt: spec.Now(), DataRevision: e.Site.Spec.DataRevision, Resources: []spec.ResourceFact{}, Facts: o.Facts, Findings: []spec.Finding{}}
	if o.TargetID == "" || o.NamespaceUID == "" {
		e.finalizeInspection(&s)
		return s, nil
	}
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
	gp, err := e.Kube.ObserveGPUs(ctx)
	if err != nil {
		s.Facts = append(s.Facts, spec.Fact{Name: "nvidia.allocatable", Status: observationStatus(err), Source: "node authorization/discovery"})
	} else {
		var total int64
		for _, count := range gp {
			var n int64
			_, _ = fmt.Sscan(count, &n)
			total += n
		}
		status := "known"
		if total == 0 {
			status = "absent"
		}
		s.Facts = append(s.Facts, spec.Fact{Name: "nvidia.allocatable", Value: fmt.Sprint(total), Status: status, Source: "Kubernetes node allocatable; not hardware qualification"})
	}
	if err := e.inspectSecrets(ctx, &s); err != nil {
		return s, err
	}
	sort.Slice(s.Resources, func(i, j int) bool {
		return s.Resources[i].Kind+"/"+s.Resources[i].Name < s.Resources[j].Kind+"/"+s.Resources[j].Name
	})
	rev, version, values, err := e.helmState(ctx)
	release := spec.Fact{Name: "helm.release", Status: observationStatus(err), Source: "Helm history and effective values"}
	if err != nil {
		if release.Status == "absent" {
			release.Status = "unavailable"
		}
		if spec.ExitCode(err) == 13 {
			release.Status = "stale"
		}
		s.Findings = append(s.Findings, spec.Finding{Code: "HELM_STATE_" + strings.ToUpper(release.Status), Severity: "blocker", Message: "Helm release state is " + release.Status, Source: release.Source})
	} else {
		s.HelmRevision, s.InstalledVersion = rev, version
		release.Value = version
		if version == "" {
			release.Status = "absent"
		}
		s.EffectiveConfigDigest, err = e.privateFingerprint(values)
		if err != nil {
			return s, err
		}
	}
	s.Facts = append(s.Facts, release)
	if s.DataRevision != "" {
		s.Facts = append(s.Facts, spec.Fact{Name: "application.dataRevision", Value: s.DataRevision, Status: "asserted", Source: "customer Site assertion; vendor operation must enforce its own schema precondition"})
	}
	e.finalizeInspection(&s)
	return s, nil
}

func (e *Engine) finalizeInspection(s *spec.TargetSnapshot) {
	present := map[string]bool{}
	for _, fact := range s.Facts {
		present[fact.Name] = true
	}
	names := []string{"kubernetes.api", "namespace.identity", "kubernetes.version", "helm.release", "nvidia.allocatable"}
	for _, kind := range []string{"Deployment", "StatefulSet", "ConfigMap", "Service", "PersistentVolumeClaim", "Secret"} {
		names = append(names, "inventory/"+kind)
	}
	for name := range e.Site.Spec.SecretRefs {
		names = append(names, "secret/"+name)
	}
	for _, name := range e.Site.Spec.ImagePullSecrets {
		names = append(names, "secret/image-pull-"+name)
	}
	for _, name := range names {
		if !present[name] {
			s.Facts = append(s.Facts, spec.Fact{Name: name, Status: "unknown", Source: "read was not completed"})
		}
	}
	sort.Slice(s.Facts, func(i, j int) bool { return s.Facts[i].Name < s.Facts[j].Name })
	for _, fact := range s.Facts {
		inventory := strings.HasPrefix(fact.Name, "inventory/")
		required := inventory || fact.Name == "kubernetes.api" || fact.Name == "namespace.identity" || fact.Name == "helm.release"
		valid := fact.Status == "known" || fact.Status == "absent" && (inventory && fact.Value == "0" || fact.Name == "helm.release")
		if required && !valid {
			s.Findings = append(s.Findings, spec.Finding{Code: "TARGET_FACT_" + strings.ToUpper(fact.Status), Severity: "blocker", Message: fact.Name + " is " + fact.Status, Source: fact.Source})
		}
	}
}

func targetObservationError(s spec.TargetSnapshot) error {
	if s.TargetID == "" || s.NamespaceUID == "" {
		return spec.Err(10, "target identity is not established")
	}
	for _, finding := range s.Findings {
		if finding.Severity == "blocker" {
			return spec.Err(10, "required target observation is incomplete: %s", finding.Message)
		}
	}
	return nil
}

func (e *Engine) inspectSecrets(ctx context.Context, s *spec.TargetSnapshot) error {
	type binding struct {
		secret *corev1.Secret
		refs   map[string]string
	}
	bindings := map[types.NamespacedName]*binding{}
	bind := func(name string) *binding {
		id := types.NamespacedName{Namespace: e.Site.Spec.Namespace, Name: name}
		if bindings[id] == nil {
			bindings[id] = &binding{refs: map[string]string{}}
		}
		return bindings[id]
	}
	for name, ref := range e.Site.Spec.SecretRefs {
		if ref.File != "" {
			value, err := e.privateFileFingerprint(ref.File)
			fact := spec.Fact{Name: "secret/" + name, Status: observationStatus(err), Source: "local private-file reference"}
			if err == nil {
				fact.Value, fact.Status = value, "known"
			}
			s.Facts = append(s.Facts, fact)
			continue
		}
		if ref.Namespace != "" && ref.Namespace != e.Site.Spec.Namespace {
			return spec.Err(16, "cross-namespace secret reference is unsupported")
		}
		bind(ref.Name).refs["secret/"+name] = ref.Key
	}
	for _, name := range e.Site.Spec.ImagePullSecrets {
		if _, exists := e.Site.Spec.SecretRefs["image-pull-"+name]; exists {
			return spec.Err(16, "image pull Secret fact name collides with a Site secret reference")
		}
		bind(name).refs["secret/image-pull-"+name] = ""
	}
	secrets, err := e.Kube.Client.CoreV1().Secrets(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/instance=" + e.Site.Spec.ReleaseName})
	if err != nil {
		s.Facts = append(s.Facts, inventoryFact("Secret", 0, err))
		secrets = &corev1.SecretList{}
	} else {
		s.Facts = append(s.Facts, inventoryFact("Secret", len(secrets.Items), nil))
	}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		if err := checkOwner(&secret.ObjectMeta, e.Site.Spec.ReleaseName, nil); err != nil {
			return err
		}
		bind(secret.Name).secret = secret
	}
	for id, binding := range bindings {
		secret := binding.secret
		managed := secret != nil
		if !managed {
			secret, err = e.Kube.Client.CoreV1().Secrets(id.Namespace).Get(ctx, id.Name, metav1.GetOptions{})
			if err != nil {
				for name := range binding.refs {
					s.Facts = append(s.Facts, spec.Fact{Name: name, Status: observationStatus(err), Source: "Kubernetes Secret access"})
				}
				continue
			}
		}
		// Managed Secrets bind every key because workloads may consume undeclared keys.
		data := map[string][]byte{}
		full := managed || len(binding.refs) == 0
		for _, key := range binding.refs {
			if key == "" {
				full = true
			} else if value, ok := secret.Data[key]; ok {
				data[key] = value
			}
		}
		if full {
			data = secret.Data
		}
		value, err := e.secretFingerprint(secret, data)
		if err != nil {
			return err
		}
		if managed {
			body, err := spec.Canonical(resourceBinding(secret.ObjectMeta, value))
			if err != nil {
				return errors.New("cannot encode Secret ownership binding")
			}
			owned, err := e.privateFingerprint(append([]byte("cinderlock.inspection-secret-ownership.v1\x00"), body...))
			if err != nil {
				return errors.New("cannot fingerprint Secret ownership binding")
			}
			s.Resources = append(s.Resources, spec.ResourceFact{Kind: "Secret", Namespace: id.Namespace, Name: id.Name, UID: string(secret.UID), Fingerprint: owned})
			s.Facts = append(s.Facts, spec.Fact{Name: "readiness/Secret/" + id.Name, Value: "true", Status: "known", Source: "Kubernetes resource status"})
		}
		for name, key := range binding.refs {
			fact := spec.Fact{Name: name, Value: value, Status: "known", Source: "Kubernetes Secret private binding"}
			if _, ok := secret.Data[key]; key != "" && !ok {
				fact.Value, fact.Status, fact.Source = "", "absent", "referenced Kubernetes Secret key is absent"
			}
			s.Facts = append(s.Facts, fact)
		}
	}
	return nil
}

func (e *Engine) secretFingerprint(secret *corev1.Secret, data map[string][]byte) (string, error) {
	body, err := spec.Canonical(struct {
		Namespace, Name, UID string
		Type                 corev1.SecretType
		Data                 map[string][]byte
	}{secret.Namespace, secret.Name, string(secret.UID), secret.Type, data})
	if err != nil {
		return "", errors.New("cannot encode private Secret binding")
	}
	value, err := e.privateFingerprint(append([]byte("cinderlock.inspection-secret.v1\x00"), body...))
	if err != nil {
		return "", errors.New("cannot fingerprint private Secret binding")
	}
	return value, nil
}

func (e *Engine) privateFileFingerprint(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("cannot open private Secret file: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return "", errors.New("Secret file must be a private regular file of at most one MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return "", errors.New("cannot capture bounded private Secret file")
	}
	return e.privateFingerprint(append([]byte("cinderlock.inspection-secret-file.v1\x00"), data...))
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
		if len(transition.IntermediateReleases) != 0 {
			block("INTERMEDIATE_RELEASE_REQUIRED", "apply the separately admitted intermediate releases in declared order before planning this target: "+strings.Join(transition.IntermediateReleases, " -> "))
		}
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
		if _, ok := e.Site.Spec.SecretRefs[req.SecretRef]; !ok {
			block("LICENSE_MISSING", "offline license reference is missing")
		}
		if err := licenseTimeError(req, time.Now()); err != nil {
			block("LICENSE_EXPIRED", err.Error())
		}
	}
	for _, o := range p.Operations {
		if !slices.Contains(e.Site.Spec.AllowedActions, o.Type) || !slices.Contains(policy.Spec.AllowedActions, o.Type) {
			block("CAPABILITY_DENIED", "operation type not permitted by both site and policy: "+o.Type)
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
	if p.Kind == "Plan" || p.Kind == "RecoveryPlan" {
		if err := licenseTimeError(v.Index.Lock.Release.Spec.License, time.Now()); err != nil {
			return err
		}
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
	if err := targetObservationError(current); err != nil {
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
	if findings := e.secretFindings(p, current, v); len(findings) > 0 {
		return spec.Err(10, "%s", findings[0].Message)
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
		if len(t.IntermediateReleases) != 0 {
			return spec.Err(10, "declared intermediate releases must be applied before the target release")
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
	if err := targetObservationError(current); err != nil {
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
	if err := targetObservationError(after); err != nil {
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
