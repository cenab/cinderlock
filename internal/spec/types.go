package spec

import "time"

const APIVersion = "cinderlock.dev/v1alpha1"
const BundleDomain = "cinderlock.bundle-index.v1"
const AuthorizationDomain = "cinderlock.execution-authorization.v1"

type Header struct {
	APIVersion    string   `json:"apiVersion" yaml:"apiVersion"`
	Kind          string   `json:"kind" yaml:"kind"`
	SchemaVersion int      `json:"schemaVersion" yaml:"schemaVersion"`
	Metadata      Metadata `json:"metadata" yaml:"metadata"`
}
type Metadata struct {
	Name        string `json:"name,omitempty" yaml:"name,omitempty"`
	Application string `json:"application,omitempty" yaml:"application,omitempty"`
	Version     string `json:"version,omitempty" yaml:"version,omitempty"`
	Channel     string `json:"channel,omitempty" yaml:"channel,omitempty"`
	Sequence    int64  `json:"sequence,omitempty" yaml:"sequence,omitempty"`
}

func NewHeader(kind string) Header {
	return Header{APIVersion: APIVersion, Kind: kind, SchemaVersion: 1}
}

type Release struct {
	Header `yaml:",inline"`
	Spec   ReleaseSpec `json:"spec" yaml:"spec"`
}
type ReleaseSpec struct {
	StorageBudgets []StorageBudget     `json:"storageBudgets,omitempty" yaml:"storageBudgets,omitempty"`
	Profile        string              `json:"profile" yaml:"profile"`
	Deployment     Deployment          `json:"deployment" yaml:"deployment"`
	Assets         []Asset             `json:"assets" yaml:"assets"`
	AIProfile      AIProfile           `json:"aiProfile" yaml:"aiProfile"`
	Transitions    []Transition        `json:"transitions" yaml:"transitions"`
	Operations     []Operation         `json:"operations" yaml:"operations"`
	Checks         []Check             `json:"checks" yaml:"checks"`
	RequiredChecks []string            `json:"requiredChecks" yaml:"requiredChecks"`
	Recovery       []Recovery          `json:"recovery" yaml:"recovery"`
	MinFreeBytes   int64               `json:"minFreeBytes,omitempty" yaml:"minFreeBytes,omitempty"`
	License        *LicenseRequirement `json:"license,omitempty" yaml:"license,omitempty"`
}
type Deployment struct {
	Configuration *ConfigurationContract `json:"configuration,omitempty" yaml:"configuration,omitempty"`
	Type          string                 `json:"type" yaml:"type"`
	Chart         string                 `json:"chart" yaml:"chart"`
	ReleaseName   string                 `json:"releaseName,omitempty" yaml:"releaseName,omitempty"`
	Namespace     string                 `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Values        []string               `json:"values,omitempty" yaml:"values,omitempty"`
	ImageBindings []ImageBinding         `json:"imageBindings,omitempty" yaml:"imageBindings,omitempty"`
	AllowedKinds  []string               `json:"allowedKinds,omitempty" yaml:"allowedKinds,omitempty"`
	GitOps        *GitOps                `json:"gitOps,omitempty" yaml:"gitOps,omitempty"`
}
type GitOps struct {
	Owner    string `json:"owner" yaml:"owner"`
	Revision string `json:"revision" yaml:"revision"`
	Path     string `json:"path" yaml:"path"`
}
type ImageBinding struct {
	Asset      string `json:"asset" yaml:"asset"`
	ValuesPath string `json:"valuesPath" yaml:"valuesPath"`
}
type Asset struct {
	AllowedRedirectHosts []string `json:"allowedRedirectHosts,omitempty" yaml:"allowedRedirectHosts,omitempty"`
	ID                   string   `json:"id" yaml:"id"`
	Type                 string   `json:"type" yaml:"type"`
	Source               string   `json:"source" yaml:"source"`
	Platform             string   `json:"platform,omitempty" yaml:"platform,omitempty"`
	Digest               string   `json:"digest,omitempty" yaml:"digest,omitempty"`
	License              string   `json:"license,omitempty" yaml:"license,omitempty"`
	MediaType            string   `json:"mediaType,omitempty" yaml:"mediaType,omitempty"`
	Optional             bool     `json:"optional,omitempty" yaml:"optional,omitempty"`
}
type AIProfile struct {
	ProbeImage        string   `json:"probeImage,omitempty" yaml:"probeImage,omitempty"`
	ModelAsset        string   `json:"modelAsset,omitempty" yaml:"modelAsset,omitempty"`
	TokenizerAsset    string   `json:"tokenizerAsset,omitempty" yaml:"tokenizerAsset,omitempty"`
	RuntimeAsset      string   `json:"runtimeAsset,omitempty" yaml:"runtimeAsset,omitempty"`
	AdapterAsset      string   `json:"adapterAsset,omitempty" yaml:"adapterAsset,omitempty"`
	EmbeddingRevision string   `json:"embeddingRevision,omitempty" yaml:"embeddingRevision,omitempty"`
	IndexRevision     string   `json:"indexRevision,omitempty" yaml:"indexRevision,omitempty"`
	GPUModels         []string `json:"gpuModels,omitempty" yaml:"gpuModels,omitempty"`
	GPUCount          int64    `json:"gpuCount,omitempty" yaml:"gpuCount,omitempty"`
	MinGPUMemoryMiB   int64    `json:"minGPUMemoryMiB,omitempty" yaml:"minGPUMemoryMiB,omitempty"`
	DriverVersions    []string `json:"driverVersions,omitempty" yaml:"driverVersions,omitempty"`
	Precision         string   `json:"precision,omitempty" yaml:"precision,omitempty"`
}
type LicenseRequirement struct {
	Mode      string `json:"mode" yaml:"mode"`
	SecretRef string `json:"secretRef" yaml:"secretRef"`
	Check     string `json:"check" yaml:"check"`
	// MaxAgeSeconds bounds the original validation worker's age, not issuance.
	MaxAgeSeconds int64  `json:"maxAgeSeconds" yaml:"maxAgeSeconds"`
	RenewalAsset  string `json:"renewalAsset" yaml:"renewalAsset"`
	ExpiresAt     string `json:"expiresAt,omitempty" yaml:"expiresAt,omitempty"`
}
type Transition struct {
	ID          string `json:"id" yaml:"id"`
	FromRelease string `json:"fromRelease" yaml:"fromRelease"`
	// An intermediate route cannot execute as a direct transition.
	IntermediateReleases  []string `json:"intermediateReleases,omitempty" yaml:"intermediateReleases,omitempty"`
	FromDataRevision      string   `json:"fromDataRevision,omitempty" yaml:"fromDataRevision,omitempty"`
	ToDataRevision        string   `json:"toDataRevision,omitempty" yaml:"toDataRevision,omitempty"`
	FromEmbeddingRevision string   `json:"fromEmbeddingRevision,omitempty" yaml:"fromEmbeddingRevision,omitempty"`
	ReindexOperation      string   `json:"reindexOperation,omitempty" yaml:"reindexOperation,omitempty"`
	Operations            []string `json:"operations" yaml:"operations"`
	Recovery              string   `json:"recovery" yaml:"recovery"`
}
type Operation struct {
	ModelSubPath     string   `json:"modelSubPath,omitempty" yaml:"modelSubPath,omitempty"`
	NodeName         string   `json:"nodeName,omitempty" yaml:"nodeName,omitempty"`
	NodeUID          string   `json:"nodeUID,omitempty" yaml:"nodeUID,omitempty"`
	GPUCount         int64    `json:"gpuCount,omitempty" yaml:"gpuCount,omitempty"`
	ID               string   `json:"id" yaml:"id"`
	Type             string   `json:"type" yaml:"type"`
	DependsOn        []string `json:"dependsOn,omitempty" yaml:"dependsOn,omitempty"`
	Image            string   `json:"image,omitempty" yaml:"image,omitempty"`
	Asset            string   `json:"asset,omitempty" yaml:"asset,omitempty"`
	Command          []string `json:"command,omitempty" yaml:"command,omitempty"`
	Args             []string `json:"args,omitempty" yaml:"args,omitempty"`
	Service          string   `json:"service,omitempty" yaml:"service,omitempty"`
	TimeoutSeconds   int64    `json:"timeoutSeconds,omitempty" yaml:"timeoutSeconds,omitempty"`
	Idempotent       bool     `json:"idempotent,omitempty" yaml:"idempotent,omitempty"`
	ReconcileCommand []string `json:"reconcileCommand,omitempty" yaml:"reconcileCommand,omitempty"`
	ExpectedExitCode int      `json:"expectedExitCode,omitempty" yaml:"expectedExitCode,omitempty"`
	SecretRefs       []string `json:"secretRefs,omitempty" yaml:"secretRefs,omitempty"`
	PVC              string   `json:"pvc,omitempty" yaml:"pvc,omitempty"`
	MountPath        string   `json:"mountPath,omitempty" yaml:"mountPath,omitempty"`
	StorageClass     string   `json:"storageClass,omitempty" yaml:"storageClass,omitempty"`
	StorageBytes     int64    `json:"storageBytes,omitempty" yaml:"storageBytes,omitempty"`
	Destructive      bool     `json:"destructive,omitempty" yaml:"destructive,omitempty"`

	Script *ScriptContract `json:"script,omitempty" yaml:"script,omitempty"`
}
type Check struct {
	ID               string   `json:"id" yaml:"id"`
	Type             string   `json:"type" yaml:"type"`
	Domain           string   `json:"domain" yaml:"domain"`
	Required         bool     `json:"required" yaml:"required"`
	Image            string   `json:"image,omitempty" yaml:"image,omitempty"`
	Command          []string `json:"command,omitempty" yaml:"command,omitempty"`
	URL              string   `json:"url,omitempty" yaml:"url,omitempty"`
	Method           string   `json:"method,omitempty" yaml:"method,omitempty"`
	ExpectedStatus   int      `json:"expectedStatus,omitempty" yaml:"expectedStatus,omitempty"`
	BodyContains     string   `json:"bodyContains,omitempty" yaml:"bodyContains,omitempty"`
	ExpectedExitCode int      `json:"expectedExitCode,omitempty" yaml:"expectedExitCode,omitempty"`
	TimeoutSeconds   int64    `json:"timeoutSeconds,omitempty" yaml:"timeoutSeconds,omitempty"`
	Fixtures         []string `json:"fixtures,omitempty" yaml:"fixtures,omitempty"`
	SecretRefs       []string `json:"secretRefs,omitempty" yaml:"secretRefs,omitempty"`
	SyntheticData    string   `json:"syntheticData,omitempty" yaml:"syntheticData,omitempty"`

	ObservationContract *ObservationContract `json:"observationContract,omitempty" yaml:"observationContract,omitempty"`
	Script              *ScriptContract      `json:"script,omitempty" yaml:"script,omitempty"`

	CASecretRef            string `json:"caSecretRef,omitempty" yaml:"caSecretRef,omitempty"`
	AuthorizationSecretRef string `json:"authorizationSecretRef,omitempty" yaml:"authorizationSecretRef,omitempty"`
}
type Recovery struct {
	ID             string      `json:"id" yaml:"id"`
	ToRelease      string      `json:"toRelease" yaml:"toRelease"`
	DataRevision   string      `json:"dataRevision,omitempty" yaml:"dataRevision,omitempty"`
	Destructive    bool        `json:"destructive,omitempty" yaml:"destructive,omitempty"`
	RequiresBackup bool        `json:"requiresBackup,omitempty" yaml:"requiresBackup,omitempty"`
	Operations     []Operation `json:"operations" yaml:"operations"`
	Checks         []Check     `json:"checks" yaml:"checks"`
}
type FileRecord struct {
	Path   string `json:"path" yaml:"path"`
	Digest string `json:"digest" yaml:"digest"`
	Size   int64  `json:"size" yaml:"size"`
	Mode   uint32 `json:"mode,omitempty" yaml:"mode,omitempty"`
}
type Descriptor struct {
	Path      string `json:"path" yaml:"path"`
	Digest    string `json:"digest" yaml:"digest"`
	Size      int64  `json:"size" yaml:"size"`
	MediaType string `json:"mediaType,omitempty" yaml:"mediaType,omitempty"`
}
type LockedAsset struct {
	ID             string       `json:"id" yaml:"id"`
	Type           string       `json:"type" yaml:"type"`
	Source         string       `json:"source" yaml:"source"`
	Digest         string       `json:"digest" yaml:"digest"`
	Size           int64        `json:"size" yaml:"size"`
	Platform       string       `json:"platform,omitempty" yaml:"platform,omitempty"`
	MediaType      string       `json:"mediaType,omitempty" yaml:"mediaType,omitempty"`
	License        string       `json:"license,omitempty" yaml:"license,omitempty"`
	Files          []FileRecord `json:"files,omitempty" yaml:"files,omitempty"`
	RootDescriptor *Descriptor  `json:"rootDescriptor,omitempty" yaml:"rootDescriptor,omitempty"`
}
type ReleaseLock struct {
	Header       `yaml:",inline"`
	Release      Release       `json:"release" yaml:"release"`
	SourceDigest string        `json:"sourceDigest" yaml:"sourceDigest"`
	Assets       []LockedAsset `json:"assets" yaml:"assets"`
	Toolchain    Toolchain     `json:"toolchain" yaml:"toolchain"`
}
type Toolchain struct {
	Go         string `json:"go,omitempty" yaml:"go,omitempty"`
	CLI        string `json:"cli,omitempty" yaml:"cli,omitempty"`
	Helm       string `json:"helm,omitempty" yaml:"helm,omitempty"`
	HelmDigest string `json:"helmDigest,omitempty" yaml:"helmDigest,omitempty"`
}
type BundleIndex struct {
	Inventory            *Descriptor `json:"inventory,omitempty" yaml:"inventory,omitempty"`
	Header               `yaml:",inline"`
	Domain               string       `json:"domain" yaml:"domain"`
	Lock                 ReleaseLock  `json:"lock" yaml:"lock"`
	Payloads             []Descriptor `json:"payloads" yaml:"payloads"`
	RequiredCapabilities []string     `json:"requiredCapabilities,omitempty" yaml:"requiredCapabilities,omitempty"`
}

type Site struct {
	Header `yaml:",inline"`
	Spec   SiteSpec `json:"spec" yaml:"spec"`
}
type SiteSpec struct {
	AdmissionDryRun               bool                 `json:"admissionDryRun,omitempty" yaml:"admissionDryRun,omitempty"`
	StorageProfile                string               `json:"storageProfile,omitempty" yaml:"storageProfile,omitempty"`
	StorageOperatorPath           string               `json:"storageOperatorPath,omitempty" yaml:"storageOperatorPath,omitempty"`
	StorageCapacities             []StorageCapacity    `json:"storageCapacities,omitempty" yaml:"storageCapacities,omitempty"`
	RegistryAuthHosts             []string             `json:"registryAuthHosts,omitempty" yaml:"registryAuthHosts,omitempty"`
	RegistryAuthRef               string               `json:"registryAuthRef,omitempty" yaml:"registryAuthRef,omitempty"`
	ImagePullSecrets              []string             `json:"imagePullSecrets,omitempty" yaml:"imagePullSecrets,omitempty"`
	HardwareEvidenceMaxAgeSeconds int64                `json:"hardwareEvidenceMaxAgeSeconds,omitempty" yaml:"hardwareEvidenceMaxAgeSeconds,omitempty"`
	HardwareEvidence              string               `json:"hardwareEvidence,omitempty" yaml:"hardwareEvidence,omitempty"`
	RegistryPlainHTTP             bool                 `json:"registryPlainHTTP,omitempty" yaml:"registryPlainHTTP,omitempty"`
	RegistryCAFile                string               `json:"registryCAFile,omitempty" yaml:"registryCAFile,omitempty"`
	HelperImage                   string               `json:"helperImage,omitempty" yaml:"helperImage,omitempty"`
	Kubeconfig                    string               `json:"kubeconfig" yaml:"kubeconfig"`
	Context                       string               `json:"context" yaml:"context"`
	Namespace                     string               `json:"namespace" yaml:"namespace"`
	ReleaseName                   string               `json:"releaseName" yaml:"releaseName"`
	Registry                      string               `json:"registry,omitempty" yaml:"registry,omitempty"`
	TrustPolicy                   string               `json:"trustPolicy" yaml:"trustPolicy"`
	HelmPath                      string               `json:"helmPath,omitempty" yaml:"helmPath,omitempty"`
	HelmDigest                    string               `json:"helmDigest,omitempty" yaml:"helmDigest,omitempty"`
	Profile                       string               `json:"profile" yaml:"profile"`
	ClusterID                     string               `json:"clusterID,omitempty" yaml:"clusterID,omitempty"`
	NamespaceUID                  string               `json:"namespaceUID,omitempty" yaml:"namespaceUID,omitempty"`
	Values                        map[string]any       `json:"values,omitempty" yaml:"values,omitempty"`
	SecretRefs                    map[string]SecretRef `json:"secretRefs,omitempty" yaml:"secretRefs,omitempty"`
	AllowedHosts                  []string             `json:"allowedHosts,omitempty" yaml:"allowedHosts,omitempty"`
	AllowExecAuth                 bool                 `json:"allowExecAuth,omitempty" yaml:"allowExecAuth,omitempty"`
	CapacityBytes                 int64                `json:"capacityBytes,omitempty" yaml:"capacityBytes,omitempty"`
	DataRevision                  string               `json:"dataRevision,omitempty" yaml:"dataRevision,omitempty"`
	EmbeddingRevision             string               `json:"embeddingRevision,omitempty" yaml:"embeddingRevision,omitempty"`
	BackupRef                     string               `json:"backupRef,omitempty" yaml:"backupRef,omitempty"`
	AllowedActions                []string             `json:"allowedActions,omitempty" yaml:"allowedActions,omitempty"`
	StateDir                      string               `json:"stateDir,omitempty" yaml:"stateDir,omitempty"`
}
type SecretRef struct {
	Name      string `json:"name,omitempty" yaml:"name,omitempty"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Key       string `json:"key,omitempty" yaml:"key,omitempty"`
	File      string `json:"file,omitempty" yaml:"file,omitempty"`
}
type TrustedKey struct {
	ID           string   `json:"id" yaml:"id"`
	PublicKey    string   `json:"publicKey" yaml:"publicKey"`
	Applications []string `json:"applications" yaml:"applications"`
	Channels     []string `json:"channels" yaml:"channels"`
	Roles        []string `json:"roles,omitempty" yaml:"roles,omitempty"`
	Revoked      bool     `json:"revoked,omitempty" yaml:"revoked,omitempty"`
}
type TrustPolicy struct {
	Header `yaml:",inline"`
	Spec   TrustSpec `json:"spec" yaml:"spec"`
}
type TrustSpec struct {
	Epoch                int64            `json:"epoch" yaml:"epoch"`
	Keys                 []TrustedKey     `json:"keys" yaml:"keys"`
	AllowedActions       []string         `json:"allowedActions" yaml:"allowedActions"`
	MinSequence          map[string]int64 `json:"minSequence,omitempty" yaml:"minSequence,omitempty"`
	AllowInteractive     bool             `json:"allowInteractive,omitempty" yaml:"allowInteractive,omitempty"`
	RequireAuthorization bool             `json:"requireAuthorization,omitempty" yaml:"requireAuthorization,omitempty"`
	ExpiresAt            string           `json:"expiresAt,omitempty" yaml:"expiresAt,omitempty"`
}
type Signature struct {
	KeyID     string `json:"keyID" yaml:"keyID"`
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	Signature string `json:"signature" yaml:"signature"`
}

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Source   string `json:"source,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}
type Fact struct {
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Status string `json:"status"`
	Source string `json:"source"`
}
type ResourceFact struct {
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	UID         string `json:"uid"`
	Fingerprint string `json:"fingerprint"`
}
type TargetSnapshot struct {
	Header                `yaml:",inline"`
	SiteID                string         `json:"siteID"`
	TargetID              string         `json:"targetID"`
	NamespaceUID          string         `json:"namespaceUID"`
	ObservedAt            string         `json:"observedAt"`
	HelmRevision          int64          `json:"helmRevision"`
	InstalledVersion      string         `json:"installedVersion"`
	EffectiveConfigDigest string         `json:"effectiveConfigDigest"`
	DataRevision          string         `json:"dataRevision,omitempty"`
	Resources             []ResourceFact `json:"resources"`
	Facts                 []Fact         `json:"facts"`
	Findings              []Finding      `json:"findings"`
}
type Plan struct {
	ConfigurationReview *ConfigurationReview `json:"configurationReview,omitempty" yaml:"configurationReview,omitempty"`
	Storage             *StorageAssessment   `json:"storage,omitempty" yaml:"storage,omitempty"`
	DesiredStateDigest  string               `json:"desiredStateDigest,omitempty" yaml:"desiredStateDigest,omitempty"`
	RetainedResources   []ResourceFact       `json:"retainedResources,omitempty" yaml:"retainedResources,omitempty"`
	SourceSiteDigest    string               `json:"sourceSiteDigest" yaml:"sourceSiteDigest"`
	Header              `yaml:",inline"`
	BundlePath          string         `json:"bundlePath"`
	BundleDigest        string         `json:"bundleDigest"`
	SitePath            string         `json:"sitePath"`
	SiteDigest          string         `json:"siteDigest"`
	PolicyDigest        string         `json:"policyDigest"`
	PolicyEpoch         int64          `json:"policyEpoch"`
	Snapshot            TargetSnapshot `json:"snapshot"`
	SnapshotDigest      string         `json:"snapshotDigest"`
	SourceVersion       string         `json:"sourceVersion"`
	TargetVersion       string         `json:"targetVersion"`
	TransitionID        string         `json:"transitionID"`
	Operations          []Operation    `json:"operations"`
	Checks              []Check        `json:"checks"`
	RequiredChecks      []string       `json:"requiredChecks"`
	Recovery            []Recovery     `json:"recovery"`
	Findings            []Finding      `json:"findings"`
	CreatedAt           string         `json:"createdAt"`
	Executable          bool           `json:"executable"`
	Destructive         bool           `json:"destructive,omitempty"`
	SourceRun           string         `json:"sourceRun,omitempty"`
}
type Authorization struct {
	Header       `yaml:",inline"`
	PlanDigest   string    `json:"planDigest"`
	PlanKind     string    `json:"planKind"`
	TargetID     string    `json:"targetID"`
	PolicyDigest string    `json:"policyDigest"`
	PolicyEpoch  int64     `json:"policyEpoch"`
	Actions      []string  `json:"actions"`
	ExpiresAt    string    `json:"expiresAt"`
	Nonce        string    `json:"nonce"`
	Signature    Signature `json:"signature"`
}
type StepResult struct {
	ID         string `json:"id"`
	Attempt    int    `json:"attempt"`
	Status     string `json:"status"`
	StartedAt  string `json:"startedAt,omitempty"`
	FinishedAt string `json:"finishedAt,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Error      string `json:"error,omitempty"`
	ExternalID string `json:"externalID,omitempty"`
}
type CheckResult struct {
	ID             string `json:"id"`
	Domain         string `json:"domain"`
	Required       bool   `json:"required"`
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	Evidence       string `json:"evidence,omitempty"`
	DurationMillis int64  `json:"durationMillis,omitempty"`

	Observations *CheckObservations `json:"observations,omitempty"`
}
type RunResult struct {
	Header           `yaml:",inline"`
	RunID            string            `json:"runID"`
	PlanDigest       string            `json:"planDigest"`
	BundleDigest     string            `json:"bundleDigest"`
	SiteID           string            `json:"siteID"`
	TargetID         string            `json:"targetID"`
	State            string            `json:"state"`
	Acceptance       string            `json:"acceptance"`
	StartedAt        string            `json:"startedAt"`
	FinishedAt       string            `json:"finishedAt,omitempty"`
	Steps            []StepResult      `json:"steps"`
	Checks           []CheckResult     `json:"checks"`
	Domains          map[string]string `json:"domains"`
	Findings         []Finding         `json:"findings"`
	RecoveryCoverage string            `json:"recoveryCoverage"`
	OfflineCoverage  string            `json:"offlineCoverage"`
	Error            string            `json:"error,omitempty"`
	SourceRun        string            `json:"sourceRun,omitempty"`
}

func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
