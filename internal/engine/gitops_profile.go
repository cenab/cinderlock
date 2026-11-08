package engine

import (
	"bytes"
	"context"
	"net/url"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
)

// GitOpsProfileContract selects one fixed, read-only controller adapter.
type GitOpsProfileContract struct {
	spec.Header
	Profile          string                  `json:"profile"`
	Namespace        string                  `json:"namespace"`
	Name             string                  `json:"name"`
	UID              string                  `json:"uid"`
	Repository       string                  `json:"repository"`
	RepositoryURL    string                  `json:"repositoryURL"`
	AcceptedRevision string                  `json:"acceptedRevision"`
	ManifestDigest   string                  `json:"manifestDigest"`
	NotBefore        string                  `json:"notBefore"`
	MaxAgeSeconds    int64                   `json:"maxAgeSeconds"`
	InstallationID   string                  `json:"installationID,omitempty"`
	Reversion        *GitOpsProfileReversion `json:"reversion,omitempty"`
}

type GitOpsProfileReversion struct {
	PreviousRevision string `json:"previousRevision"`
	RestoredRevision string `json:"restoredRevision"`
}

type GitOpsProfileResourceObservation struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	Namespace          string `json:"namespace"`
	Name               string `json:"name"`
	UID                string `json:"uid,omitempty"`
	ResourceVersion    string `json:"resourceVersion,omitempty"`
	Generation         int64  `json:"generation,omitempty"`
	Active             bool   `json:"active"`
	DesiredFieldsMatch bool   `json:"desiredFieldsMatch"`
	TrackingMatch      bool   `json:"trackingMatch"`
	OwnershipMatch     bool   `json:"ownershipMatch"`
	Healthy            bool   `json:"healthy"`
	ControllerHealth   string `json:"controllerHealth,omitempty"`
	SyncStatus         string `json:"syncStatus,omitempty"`
	OperationStatus    string `json:"operationStatus,omitempty"`
}

// GitOpsProfileObservation contains metadata and match facts, never object values.
type GitOpsProfileObservation struct {
	spec.Header
	Profile               string                             `json:"profile"`
	Owner                 string                             `json:"owner"`
	Namespace             string                             `json:"namespace"`
	Name                  string                             `json:"name"`
	UID                   string                             `json:"uid,omitempty"`
	ResourceVersion       string                             `json:"resourceVersion,omitempty"`
	Generation            int64                              `json:"generation,omitempty"`
	AcceptedRevision      string                             `json:"acceptedRevision"`
	ObservedRevision      string                             `json:"observedRevision,omitempty"`
	RepositoryURLDigest   string                             `json:"repositoryURLDigest"`
	ManifestDigest        string                             `json:"manifestDigest"`
	BundleDigest          string                             `json:"bundleDigest"`
	SiteDigest            string                             `json:"siteDigest"`
	SourceSiteDigest      string                             `json:"sourceSiteDigest,omitempty"`
	PolicyDigest          string                             `json:"policyDigest"`
	SourcePolicyDigest    string                             `json:"sourcePolicyDigest,omitempty"`
	ContractDigest        string                             `json:"contractDigest"`
	SourcePath            string                             `json:"sourcePath"`
	SourceBlob            string                             `json:"sourceBlob,omitempty"`
	TargetID              string                             `json:"targetID,omitempty"`
	NamespaceUID          string                             `json:"namespaceUID,omitempty"`
	ObservedAt            string                             `json:"observedAt"`
	ReconciledAt          string                             `json:"reconciledAt,omitempty"`
	OperationStartedAt    string                             `json:"operationStartedAt,omitempty"`
	OperationFinishedAt   string                             `json:"operationFinishedAt,omitempty"`
	SyncStatus            string                             `json:"syncStatus,omitempty"`
	HealthStatus          string                             `json:"healthStatus,omitempty"`
	OperationPhase        string                             `json:"operationPhase,omitempty"`
	Resources             []GitOpsProfileResourceObservation `json:"resources"`
	Reversion             *GitOpsReversionObservation        `json:"reversion,omitempty"`
	Findings              []spec.Finding                     `json:"findings"`
	Ready                 bool                               `json:"ready"`
	ApplicationAcceptance string                             `json:"applicationAcceptance"`
	Limit                 string                             `json:"limit"`
}

var gitOpsProfileToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

func (c GitOpsProfileContract) validate() error {
	if strings.ContainsAny(c.Repository, "\x00\r\n") || strings.Contains(c.Repository, "://") {
		return spec.Err(2, "GitOps profile requires a local repository directory")
	}
	for _, part := range strings.Split(c.Repository, "/") {
		if part == ".." {
			return spec.Err(2, "GitOps profile repository directory cannot contain a path escape")
		}
	}
	u, err := url.Parse(c.RepositoryURL)
	if spec.ValidateHeader(c.Header, "GitOpsProfileContract") != nil || c.Profile != "argocd-directory-v1" || len(validation.IsDNS1123Label(c.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(c.Name)) != 0 || !gitOpsProfileToken.MatchString(c.UID) || c.Repository == "" || err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(c.RepositoryURL, "\\#\r\n\t") || !gitOpsCommitID(c.AcceptedRevision) || !spec.ValidDigest(c.ManifestDigest) || c.MaxAgeSeconds <= 0 || c.MaxAgeSeconds > 86400 || c.InstallationID != "" && !gitOpsProfileToken.MatchString(c.InstallationID) {
		return spec.Err(2, "invalid or unsupported GitOps profile contract")
	}
	before, err := time.Parse(time.RFC3339Nano, c.NotBefore)
	if err != nil || before.IsZero() || before.After(time.Now()) {
		return spec.Err(2, "GitOps profile requires a valid nonfuture notBefore timestamp")
	}
	if c.Reversion != nil && (!gitOpsCommitID(c.Reversion.PreviousRevision) || !gitOpsCommitID(c.Reversion.RestoredRevision)) {
		return spec.Err(2, "GitOps profile reversion requires full lower-case commit IDs")
	}
	return nil
}

func (o *GitOpsProfileObservation) block(code, message string) {
	o.Ready = false
	o.Findings = append(o.Findings, spec.Finding{Code: "GITOPS_PROFILE_" + code, Severity: "blocker", Message: message})
}

// ObserveGitOpsProfile establishes bounded point-in-time evidence, never execution authority.
func (e *Engine) ObserveGitOpsProfile(ctx context.Context, v *bundle.Verified, policy spec.TrustPolicy, sitePath string, contract GitOpsProfileContract, reviewedManifest []byte) (out GitOpsProfileObservation, err error) {
	if err = contract.validate(); err != nil {
		return out, err
	}
	if e == nil || v == nil || !spec.ValidDigest(v.Digest) || spec.ValidateRelease(v.Index.Lock.Release) != nil || spec.ValidatePolicy(policy) != nil || spec.ValidateSite(e.Site) != nil || len(validation.IsDNS1123Label(e.Site.Spec.Namespace)) != 0 || sitePath == "" || e.StateDir == "" {
		return out, spec.Err(2, "GitOps profile requires a verified release, valid policy, Site source, and external state directory")
	}
	r := v.Index.Lock.Release
	declared := r.Spec.Deployment.GitOps
	if r.Spec.Deployment.Type != "gitops" || declared == nil || declared.Owner != "argocd" || !gitOpsTargetPath(declared.Path) || !gitOpsCommitID(declared.Revision) || e.Site.Spec.Profile != r.Spec.Profile {
		return out, spec.Err(10, "GitOps profile requires signed Argo CD ownership, a confined YAML path, and matching Site profile")
	}
	if !slices.Contains(e.Site.Spec.AllowedActions, "gitops-observe") || !slices.Contains(policy.Spec.AllowedActions, "gitops-observe") {
		return out, spec.Err(16, "GitOps observation capability is not admitted by both Site and policy")
	}
	if len(reviewedManifest) == 0 || len(reviewedManifest) > maxGitOpsFileBytes || !utf8.Valid(reviewedManifest) || bytes.IndexByte(reviewedManifest, 0) >= 0 || spec.Hash(reviewedManifest) != contract.ManifestDigest {
		return out, spec.Err(2, "GitOps reviewed manifest must match its exact bounded SHA-256 input")
	}
	if needsHardware(r.Spec.AIProfile) {
		return out, spec.Err(10, "hardware-dependent rendering is outside this directory profile")
	}
	desired, parseErr := e.gitOpsProfileInventory(reviewedManifest, contract)
	if parseErr != nil {
		return out, parseErr
	}
	site := e.Site
	siteDigest, siteErr := spec.Digest(site)
	policyDigest, policyErr := spec.Digest(policy)
	contractDigest, contractErr := spec.Digest(contract)
	if siteErr != nil || policyErr != nil || contractErr != nil {
		return out, spec.Err(2, "GitOps profile inputs cannot be canonically bound")
	}
	out = GitOpsProfileObservation{Header: spec.NewHeader("GitOpsProfileObservation"), Profile: contract.Profile, Owner: "argocd", Namespace: contract.Namespace, Name: contract.Name, AcceptedRevision: contract.AcceptedRevision, RepositoryURLDigest: spec.Hash([]byte(contract.RepositoryURL)), ManifestDigest: contract.ManifestDigest, BundleDigest: v.Digest, SiteDigest: siteDigest, PolicyDigest: policyDigest, ContractDigest: contractDigest, SourcePath: declared.Path, ObservedAt: spec.Now(), Resources: []GitOpsProfileResourceObservation{}, Findings: []spec.Finding{}, ApplicationAcceptance: "not_established", Limit: "Supplied-field and ownership evidence at one point in time only; general drift absence, future exclusive writers, application workflow acceptance, model/data preparation, source-tree rollback, and data recovery are not established."}
	var observedController *unstructured.Unstructured
	// Finalize after the deferred source, namespace, history, and policy reads.
	defer func() {
		if err != nil {
			return
		}
		if out.Ready && observedController != nil && !gitOpsProfileTimes(observedController, contract, nil) {
			out.block("STALE", "original controller and operation timestamps no longer meet the freshness window")
		}
		if ctx.Err() != nil {
			out.block("INTERRUPTED", "GitOps profile observation was interrupted")
		}
		out.ObservedAt = spec.Now()
	}()
	if _, checkErr := GitOpsPreparationPath(contract.Repository, e.StateDir); checkErr != nil {
		if spec.ExitCode(checkErr) == 16 {
			return GitOpsProfileObservation{}, spec.Err(2, "GitOps profile state must be outside the local source repository")
		}
		out.block("SOURCE_UNAVAILABLE", "local source repository or its external preparation location could not be established")
		return out, nil
	}
	if !e.gitOpsProfileFile(sitePath, &spec.Site{}, siteDigest, &out.SourceSiteDigest) || !e.gitOpsProfileFile(site.Spec.TrustPolicy, &spec.TrustPolicy{}, policyDigest, &out.SourcePolicyDigest) {
		out.block("BINDINGS_UNAVAILABLE", "current Site or policy source does not match the selected inputs")
		return out, nil
	}
	defer func() {
		if err != nil {
			return
		}
		currentSite, digestErr := spec.Digest(e.Site)
		sourceSite, sourcePolicy := "", ""
		if digestErr != nil || currentSite != siteDigest || spec.ValidatePolicy(policy) != nil || !e.gitOpsProfileFile(sitePath, &spec.Site{}, siteDigest, &sourceSite) || sourceSite != out.SourceSiteDigest || !e.gitOpsProfileFile(site.Spec.TrustPolicy, &spec.TrustPolicy{}, policyDigest, &sourcePolicy) || sourcePolicy != out.SourcePolicyDigest {
			out.block("BINDINGS_CHANGED", "Site or policy source changed during observation")
		}
	}()
	if e.Kube == nil || e.Kube.Client == nil || e.Kube.Config == nil {
		out.block("TARGET_UNAVAILABLE", "target Kubernetes clients are unavailable")
		return out, nil
	}
	history, absent, historyErr := e.helmHistory(ctx)
	if historyErr != nil {
		out.block("HELM_UNAVAILABLE", "selected Helm history absence could not be established")
		return out, nil
	}
	if !absent && (history.Status != "uninstalled" || history.Revision <= 0) {
		out.block("HELM_OWNER", "selected release has active, pending, or unsupported Helm history")
		return out, nil
	}
	defer func() {
		if err != nil {
			return
		}
		current, nowAbsent, historyErr := e.helmHistory(ctx)
		if historyErr != nil || nowAbsent != absent || current != history {
			out.block("HELM_CHANGED", "selected Helm history changed during controller observation")
		}
	}()
	objects, renderErr := e.renderWithContext(ctx, v, helmRenderContext{})
	var rendered []byte
	if renderErr == nil {
		rendered, renderErr = encodeObjects(objects)
	}
	if len(rendered) > maxGitOpsFileBytes {
		renderErr = spec.Err(10, "render exceeds controller profile limit")
	}
	if renderErr != nil {
		out.block("RENDER_UNAVAILABLE", "verified desired-state rendering could not be established")
		return out, nil
	}
	if !bytes.Equal(rendered, reviewedManifest) {
		return GitOpsProfileObservation{}, spec.Err(2, "GitOps reviewed manifest differs from the verified bundle and Site render")
	}
	source, sourceErr := ProposeGitOpsSource(ctx, contract.Repository, contract.AcceptedRevision, declared.Path, reviewedManifest)
	if sourceErr != nil || source.Patch != "" {
		out.block("SOURCE_MISMATCH", "accepted local HEAD, index, and signed file do not exactly match the reviewed render")
		return out, nil
	}
	out.SourceBlob = source.BaseBlob
	if !gitOpsProfileSourceFiles(ctx, source) {
		out.block("SOURCE_UNSUPPORTED", "source override files or an unreadable source directory are outside the plain-directory profile")
		return out, nil
	}
	defer func() {
		current, sourceErr := ProposeGitOpsSource(ctx, contract.Repository, contract.AcceptedRevision, declared.Path, reviewedManifest)
		if sourceErr != nil || current != source {
			out.block("SOURCE_CHANGED", "local accepted source changed during observation")
		}
	}()
	if contract.Reversion != nil {
		facts, reversionErr := ObserveGitOpsReversion(ctx, &GitOpsSourceReversion{Repository: contract.Repository, PreviousRevision: contract.Reversion.PreviousRevision, RestoredRevision: contract.Reversion.RestoredRevision}, contract.AcceptedRevision, declared.Path, reviewedManifest)
		if reversionErr != nil {
			out.block("REVERSION_UNAVAILABLE", "historical restoration of the exact signed file could not be established")
			return out, nil
		}
		out.Reversion = &facts
	}
	targetID, namespaceUID, targetOK := e.gitOpsProfileTarget(ctx, site)
	if !targetOK {
		out.block("TARGET_UNAVAILABLE", "active target namespace identity and Site pins could not be established")
		return out, nil
	}
	out.TargetID, out.NamespaceUID = targetID, namespaceUID
	defer func() {
		currentID, currentUID, ok := e.gitOpsProfileTarget(ctx, site)
		if !ok || currentID != targetID || currentUID != namespaceUID {
			out.block("TARGET_CHANGED", "target namespace identity changed during observation")
		}
	}()
	client := e.DynamicClient
	if client == nil {
		client, err = dynamic.NewForConfig(e.Kube.Config)
		if err != nil {
			out.block("CONTROLLER_UNAVAILABLE", "Argo CD observation client is unavailable")
			return out, nil
		}
	}
	applications := client.Resource(schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}).Namespace(contract.Namespace)
	application, getErr := applications.Get(ctx, contract.Name, metav1.GetOptions{})
	if getErr != nil || application == nil {
		out.block("CONTROLLER_UNAVAILABLE", "named Argo CD Application could not be read")
		return out, nil
	}
	observedController = application
	if !gitOpsProfileApplication(application, contract, site.Spec.Namespace, declared.Path, &out) {
		out.block("CONTROLLER_MISMATCH", "Application identity, source, destination, operation, or original freshness facts do not satisfy the profile")
		return out, nil
	}
	if !gitOpsProfileResources(application, desired, &out) {
		out.block("INVENTORY_MISMATCH", "controller and completed-operation inventories must exactly match the reviewed resources without hooks or pending pruning")
		return out, nil
	}
	for i, object := range desired {
		resource := object.GroupVersionKind().GroupVersion().WithResource(permissionResources[object.GetKind()].resource)
		live, liveErr := client.Resource(resource).Namespace(site.Spec.Namespace).Get(ctx, object.GetName(), metav1.GetOptions{})
		fact := &out.Resources[i]
		if liveErr != nil || live == nil {
			out.block("RESOURCE_UNAVAILABLE", "an exact reviewed live resource could not be read")
			continue
		}
		fact.Active = gitOpsProfileActive(live) && live.GetAPIVersion() == object.GetAPIVersion() && live.GetKind() == object.GetKind() && live.GetNamespace() == site.Spec.Namespace && live.GetName() == object.GetName()
		if gitOpsProfileToken.MatchString(string(live.GetUID())) {
			fact.UID = string(live.GetUID())
		}
		if gitOpsProfileToken.MatchString(live.GetResourceVersion()) {
			fact.ResourceVersion = live.GetResourceVersion()
		}
		if live.GetGeneration() > 0 {
			fact.Generation = live.GetGeneration()
		}
		fact.TrackingMatch = gitOpsProfileMetadata(live, contract, true)
		fact.DesiredFieldsMatch = gitOpsProfileFieldsMatch(object.Object, live.Object)
		fact.OwnershipMatch = gitOpsProfileManagedFields(object, live)
		fact.Healthy = gitOpsProfileLiveHealth(live)
		if !fact.Active {
			out.block("RESOURCE_INACTIVE", "a reviewed live resource lacks an active unambiguous identity")
		}
		if !fact.TrackingMatch || !fact.OwnershipMatch {
			out.block("OWNERSHIP_MISMATCH", "tracking or current managed-field ownership is missing, ambiguous, or contested")
		}
		if !fact.DesiredFieldsMatch {
			out.block("FIELDS_MISMATCH", "explicitly supplied reviewed fields differ from the current live resource")
		}
		if !fact.Healthy {
			out.block("RESOURCE_UNHEALTHY", "a live resource has unsupported behavior or its Deployment has not rolled out")
		}
	}
	after, afterErr := applications.Get(ctx, contract.Name, metav1.GetOptions{})
	if afterErr != nil || after == nil || !gitOpsProfileActive(after) || after.GetUID() != application.GetUID() || after.GetGeneration() != application.GetGeneration() || after.GetResourceVersion() != application.GetResourceVersion() || !reflect.DeepEqual(after.Object, application.Object) {
		out.block("CONTROLLER_CHANGED", "Application changed or became unavailable during resource observation")
	}
	out.Ready = len(out.Findings) == 0
	return out, nil
}

func (e *Engine) gitOpsProfileFile(file string, value any, expected string, source *string) bool {
	before, err := readKubernetesInput(file, spec.MaxDocumentBytes)
	if err != nil || spec.Decode(before, value) != nil {
		return false
	}
	if site, ok := value.(*spec.Site); ok {
		absolute, err := filepath.Abs(file)
		if err != nil {
			return false
		}
		*site = spec.ResolveSitePaths(*site, filepath.Dir(absolute))
		if site.Spec.StateDir == "" {
			site.Spec.StateDir = e.StateDir
		}
	}
	actual, err := spec.Digest(value)
	after, readErr := readKubernetesInput(file, spec.MaxDocumentBytes)
	if err != nil || readErr != nil || actual != expected || !bytes.Equal(before, after) {
		return false
	}
	*source = spec.Hash(before)
	return true
}

func gitOpsProfileSourceFiles(ctx context.Context, source GitOpsSourceChange) bool {
	git, err := gitOpsExecutable(source.Repository)
	if err != nil {
		return false
	}
	repo := gitOpsRepository{directory: source.Repository, git: git}
	tree := source.Head
	if directory := path.Dir(source.Path); directory != "." {
		tree += ":" + directory
	}
	names, err := repo.read(ctx, "ls-tree", "--name-only", "-z", tree)
	if err != nil {
		return false
	}
	// Argo reads these overrides before directory.include; filtering manifest siblings is insufficient.
	for _, name := range bytes.Split(names, []byte{0}) {
		if bytes.HasPrefix(name, []byte(".argocd-source")) && bytes.HasSuffix(name, []byte(".yaml")) {
			return false
		}
	}
	return true
}

func (e *Engine) gitOpsProfileTarget(ctx context.Context, site spec.Site) (string, string, bool) {
	if e.Kube == nil || e.Kube.Client == nil || e.Kube.Config == nil || e.Kube.Config.Host == "" || e.Kube.Namespace != site.Spec.Namespace {
		return "", "", false
	}
	ns, err := e.Kube.Client.CoreV1().Namespaces().Get(ctx, site.Spec.Namespace, metav1.GetOptions{})
	if err != nil || ns == nil || ns.Name != site.Spec.Namespace || !gitOpsProfileToken.MatchString(string(ns.UID)) || ns.DeletionTimestamp != nil {
		return "", "", false
	}
	id := TargetIdentity(e.Kube.Config.Host, string(ns.UID))
	if site.Spec.NamespaceUID != "" && site.Spec.NamespaceUID != string(ns.UID) || site.Spec.ClusterID != "" && site.Spec.ClusterID != id {
		return "", "", false
	}
	return id, string(ns.UID), true
}

func gitOpsProfileActive(u *unstructured.Unstructured) bool {
	if !gitOpsProfileToken.MatchString(string(u.GetUID())) || !gitOpsProfileToken.MatchString(u.GetResourceVersion()) {
		return false
	}
	metadata, ok := u.Object["metadata"].(map[string]any)
	if !ok {
		return false
	}
	if value, exists := metadata["deletionTimestamp"]; exists && value != nil {
		return false
	}
	if value, exists := metadata["deletionGracePeriodSeconds"]; exists && value != nil {
		return false
	}
	return true
}

func gitOpsProfileKeys(m map[string]any, allowed ...string) bool {
	if m == nil {
		return false
	}
	for key := range m {
		if !slices.Contains(allowed, key) {
			return false
		}
	}
	return true
}

func gitOpsProfileEmptySlice(value any) bool {
	if value == nil {
		return true
	}
	list, ok := value.([]any)
	return ok && len(list) == 0
}
