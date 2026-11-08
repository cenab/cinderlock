package engine

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var gpuCommand = []string{"/usr/bin/nvidia-smi"}
var gpuArguments = []string{"--query-gpu=uuid,name,memory.total,driver_version,mig.mode.current", "--format=csv,noheader,nounits"}

type GPUFact struct {
	UUID          string `json:"uuid"`
	Model         string `json:"model"`
	MemoryMiB     int64  `json:"memoryMiB"`
	DriverVersion string `json:"driverVersion"`
	MIGMode       string `json:"migMode"`
}

type HardwareEvidence struct {
	spec.Header
	RunID        string    `json:"runID"`
	TargetID     string    `json:"targetID"`
	NamespaceUID string    `json:"namespaceUID"`
	BundleDigest string    `json:"bundleDigest"`
	Profile      string    `json:"profile"`
	ObservedAt   string    `json:"observedAt"`
	ExpiresAt    string    `json:"expiresAt"`
	ProbeImage   string    `json:"probeImage"`
	NodeName     string    `json:"nodeName"`
	NodeUID      string    `json:"nodeUID"`
	JobName      string    `json:"jobName"`
	JobUID       string    `json:"jobUID"`
	PodName      string    `json:"podName"`
	PodUID       string    `json:"podUID"`
	OutputDigest string    `json:"outputDigest"`
	GPUs         []GPUFact `json:"gpus"`
}

func ParseGPUFacts(output []byte) ([]GPUFact, error) {
	if len(output) == 0 || len(output) > 64<<10 || !utf8.Valid(output) {
		return nil, errors.New("GPU probe output missing or exceeds 64 KiB")
	}
	r := csv.NewReader(bytes.NewReader(output))
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = 5
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("invalid NVIDIA GPU CSV: %w", err)
	}
	if len(rows) < 1 || len(rows) > 256 {
		return nil, errors.New("GPU probe count outside supported limits")
	}
	out := []GPUFact{}
	seen := map[string]bool{}
	for _, row := range rows {
		for i := range row {
			row[i] = strings.TrimSpace(row[i])
		}
		if !strings.HasPrefix(row[0], "GPU-") || seen[row[0]] || row[1] == "" || row[1] == "N/A" || row[3] == "" || row[3] == "N/A" || strings.ContainsAny(strings.Join(row, ""), "\x00\r\n") {
			return nil, errors.New("GPU identity/model/driver is missing, duplicated, or unsupported; MIG/MPS views need another qualified profile")
		}
		memory, err := strconv.ParseInt(row[2], 10, 64)
		if err != nil || memory <= 0 || memory > 16*1024*1024 {
			return nil, errors.New("GPU memory observation is unavailable or invalid")
		}
		for _, c := range row[3] {
			if (c < '0' || c > '9') && c != '.' {
				return nil, errors.New("GPU driver version is not a supported numeric observation")
			}
		}
		mode := strings.Trim(row[4], "[]")
		if mode != "Disabled" && mode != "N/A" && mode != "NA" {
			return nil, errors.New("enabled or unknown MIG mode needs a separately qualified device profile")
		}
		seen[row[0]] = true
		out = append(out, GPUFact{UUID: row[0], Model: row[1], MemoryMiB: memory, DriverVersion: row[3], MIGMode: mode})
	}
	return out, nil
}

func (e *Engine) ProbePlan(ctx context.Context, v *bundle.Verified, bundlePath, sitePath string, policy spec.TrustPolicy, imageAsset, nodeName string) (spec.Plan, error) {
	if err := spec.ValidateRelease(v.Index.Lock.Release); err != nil {
		return spec.Plan{}, err
	}
	if nodeName == "" {
		return spec.Plan{}, spec.Err(2, "hardware probe requires an explicit node name")
	}
	if !slices.Contains(policy.Spec.AllowedActions, "probe") || !slices.Contains(e.Site.Spec.AllowedActions, "probe") {
		return spec.Plan{}, spec.Err(16, "hardware probe capability is not approved by site and trust policy")
	}
	r := v.Index.Lock.Release
	if imageAsset == "" {
		imageAsset = r.Spec.AIProfile.ProbeImage
	}
	if imageAsset == "" {
		imageAsset = r.Spec.AIProfile.RuntimeAsset
	}
	image, err := e.image(v, imageAsset)
	if err != nil {
		return spec.Plan{}, err
	}
	_ = image
	node, err := e.Kube.Client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return spec.Plan{}, err
	}
	if node.UID == "" {
		return spec.Plan{}, spec.Err(10, "node identity unavailable")
	}
	if err := rejectSharedGPUNode(node); err != nil {
		return spec.Plan{}, err
	}
	minimum := r.Spec.AIProfile.GPUCount
	if minimum < 1 {
		minimum = 1
	}
	quantity := node.Status.Allocatable[corev1.ResourceName("nvidia.com/gpu")]
	count := quantity.Value()
	if count < minimum || count > 256 {
		return spec.Plan{}, spec.Err(10, "selected node does not advertise the requested full NVIDIA GPU count")
	}
	snapshot, err := e.Inspect(ctx)
	if err != nil {
		return spec.Plan{}, err
	}
	p := spec.Plan{Header: spec.NewHeader("ProbePlan"), BundlePath: bundlePath, BundleDigest: v.Digest, SitePath: sitePath, Snapshot: snapshot, SourceVersion: snapshot.InstalledVersion, TargetVersion: r.Metadata.Version, TransitionID: "hardware-probe", Operations: []spec.Operation{{ID: "probe-image", Type: "import", Asset: imageAsset, Idempotent: true}, {ID: "hardware-probe", Type: "probe", Asset: imageAsset, Image: imageAsset, Command: slices.Clone(gpuCommand), Args: slices.Clone(gpuArguments), NodeName: nodeName, NodeUID: string(node.UID), GPUCount: count, TimeoutSeconds: 120, Idempotent: true, DependsOn: []string{"probe-image"}}}, Recovery: r.Spec.Recovery, Checks: []spec.Check{}, RequiredChecks: []string{}, Findings: []spec.Finding{}, CreatedAt: spec.Now(), Executable: true, PolicyEpoch: policy.Spec.Epoch}
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
	if err == nil {
		e.addPolicyFloorFindings(ctx, &p)
		e.addExecutionFindings(ctx, &p, v, policy)
		e.addStorageFindings(ctx, &p, v, policy)
		e.addPermissionFindings(ctx, &p, nil)
	}
	return p, err
}

func (e *Engine) verifyProbeBinding(p spec.Plan, v *bundle.Verified) error {
	if len(p.Operations) != 2 || len(p.Checks) != 0 || len(p.RequiredChecks) != 0 || p.TransitionID != "hardware-probe" {
		return spec.Err(12, "hardware probe scope must match the fixed probe contract")
	}
	i, o := p.Operations[0], p.Operations[1]
	expectedCount := v.Index.Lock.Release.Spec.AIProfile.GPUCount
	if expectedCount < 1 {
		expectedCount = 1
	}
	if o.GPUCount < expectedCount || e.Site.Spec.Profile != v.Index.Lock.Release.Spec.Profile {
		return spec.Err(12, "probe device count/profile differs from the supported release")
	}
	if i.ID != "probe-image" || i.Type != "import" || i.Asset != o.Asset || o.ID != "hardware-probe" || o.Type != "probe" || o.Image != o.Asset || !slices.Equal(o.Command, gpuCommand) || !slices.Equal(o.Args, gpuArguments) || o.NodeName == "" || o.NodeUID == "" || o.GPUCount < 1 || o.GPUCount > 256 || o.TimeoutSeconds != 120 || o.PVC != "" || len(o.SecretRefs) != 0 || !slices.Equal(o.DependsOn, []string{"probe-image"}) {
		return spec.Err(12, "modified hardware probe command/capabilities rejected")
	}
	if _, err := e.image(v, o.Asset); err != nil {
		return err
	}
	return nil
}

func (e *Engine) probe(ctx context.Context, p spec.Plan, runID string, o spec.Operation, v *bundle.Verified) (string, error) {
	if p.Kind != "ProbePlan" {
		return "", spec.Err(16, "hardware probe cannot be authored as an application operation")
	}
	node, err := e.Kube.Client.CoreV1().Nodes().Get(ctx, o.NodeName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if string(node.UID) != o.NodeUID {
		return "", spec.Err(11, "hardware probe node identity changed")
	}
	quantity := node.Status.Allocatable[corev1.ResourceName("nvidia.com/gpu")]
	if quantity.Value() != o.GPUCount {
		return "", spec.Err(11, "node device count changed or probe does not cover the whole full-GPU node")
	}
	image, err := e.image(v, o.Image)
	if err != nil {
		return "", err
	}
	var existing HardwareEvidence
	if err := spec.Read(e.hardwarePath(runID), &existing); err == nil {
		if err := e.validateHardware(ctx, existing, v); err != nil {
			return "", err
		}
		return existing.JobName, nil
	}
	name, err := e.executeJobWithOptions(ctx, runID, o.ID, image, gpuCommand, gpuArguments, nil, "", "", o.TimeoutSeconds, &jobOptions{NodeName: o.NodeName, NodeUID: o.NodeUID, GPUCount: o.GPUCount, BundleDigest: p.BundleDigest, Profile: e.Site.Spec.Profile})
	if err != nil {
		return name, err
	}
	job, err := e.Kube.Client.BatchV1().Jobs(e.Site.Spec.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return name, err
	}
	pods, err := e.Kube.Client.CoreV1().Pods(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "job-name=" + name})
	if err != nil {
		return name, err
	}
	if len(pods.Items) != 1 {
		return name, spec.Err(13, "hardware probe needs one unambiguous completed Pod observation")
	}
	pod := pods.Items[0]
	if pod.Spec.NodeName != o.NodeName || pod.Status.Phase != corev1.PodSucceeded || pod.UID == "" || job.UID == "" {
		return name, spec.Err(13, "hardware probe lacks bound completed Pod/Job identities")
	}
	output, err := e.podLogs(ctx, pod.Name)
	if err != nil {
		return name, err
	}
	facts, err := ParseGPUFacts(output)
	if err != nil {
		return name, err
	}
	if int64(len(facts)) != o.GPUCount {
		return name, spec.Err(10, "GPU visibility does not match allocated probe count; a device isolation profile is required")
	}
	if job.Status.CompletionTime == nil {
		return name, spec.Err(13, "probe completion has no observed server timestamp")
	}
	observed := job.Status.CompletionTime.Time.UTC()
	age := e.hardwareMaxAge()
	evidence := HardwareEvidence{Header: spec.NewHeader("HardwareEvidence"), RunID: runID, TargetID: p.Snapshot.TargetID, NamespaceUID: p.Snapshot.NamespaceUID, BundleDigest: p.BundleDigest, Profile: e.Site.Spec.Profile, ObservedAt: observed.Format(time.RFC3339Nano), ExpiresAt: observed.Add(age).Format(time.RFC3339Nano), ProbeImage: image, NodeName: o.NodeName, NodeUID: o.NodeUID, JobName: name, JobUID: string(job.UID), PodName: pod.Name, PodUID: string(pod.UID), OutputDigest: spec.Hash(output), GPUs: facts}
	evidence.Metadata = p.Metadata
	if err := spec.Write(e.hardwarePath(runID), evidence); err != nil {
		return name, err
	}
	return name, nil
}

func (e *Engine) hardwarePath(runID string) string {
	return filepath.Join(e.StateDir, "hardware", runID+".json")
}
func (e *Engine) hardwareMaxAge() time.Duration {
	seconds := e.Site.Spec.HardwareEvidenceMaxAgeSeconds
	if seconds <= 0 || seconds > 86400 {
		seconds = 3600
	}
	return time.Duration(seconds) * time.Second
}

func (e *Engine) podLogs(ctx context.Context, name string) ([]byte, error) {
	if e.PodLogReader != nil {
		return e.PodLogReader(ctx, name)
	}
	limit := int64(spec.MaxObservationBytes)
	// Bound the stream locally; server-side truncation could hide extra output.
	reader, err := e.Kube.Client.CoreV1().Pods(e.Site.Spec.Namespace).GetLogs(name, &corev1.PodLogOptions{Container: "operation"}).Stream(ctx)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	b, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return b, errors.New("Job logs exceed limit")
	}
	return b, nil
}

func (e *Engine) HardwareEvidence(ctx context.Context, runID string) (HardwareEvidence, error) {
	record, err := e.Store.Run(ctx, runID)
	if err != nil {
		return HardwareEvidence{}, err
	}
	if record.State != "probe_complete" {
		return HardwareEvidence{}, spec.Err(10, "run is not a completed hardware probe")
	}
	var evidence HardwareEvidence
	if err := spec.Read(e.hardwarePath(runID), &evidence); err != nil {
		return evidence, err
	}
	if evidence.RunID != runID {
		return evidence, spec.Err(12, "hardware evidence run identity mismatch")
	}
	return evidence, e.validateHardware(ctx, evidence, nil)
}

func (e *Engine) validateConfiguredHardware(ctx context.Context, v *bundle.Verified) error {
	if e.Site.Spec.HardwareEvidence == "" {
		return spec.Err(10, "fresh target-bound hardware evidence is required; create and authorize a separate hardware probe plan")
	}
	var evidence HardwareEvidence
	if err := spec.Read(e.Site.Spec.HardwareEvidence, &evidence); err != nil {
		return err
	}
	return e.validateHardware(ctx, evidence, v)
}

func (e *Engine) validateHardware(ctx context.Context, h HardwareEvidence, v *bundle.Verified) error {
	if err := spec.ValidateHeader(h.Header, "HardwareEvidence"); err != nil {
		return err
	}
	observed, err := time.Parse(time.RFC3339Nano, h.ObservedAt)
	if err != nil {
		return spec.Err(10, "hardware evidence observation time invalid")
	}
	expiry, err := time.Parse(time.RFC3339Nano, h.ExpiresAt)
	if err != nil || !time.Now().Before(expiry) || time.Now().Before(observed.Add(-time.Minute)) || time.Since(observed) > e.hardwareMaxAge() {
		return spec.Err(10, "hardware evidence is expired or clock conditions are invalid")
	}
	if h.Profile != e.Site.Spec.Profile || v != nil && h.BundleDigest != v.Digest {
		return spec.Err(11, "hardware evidence belongs to another bundle or profile")
	}
	ns, err := e.Kube.Client.CoreV1().Namespaces().Get(ctx, e.Site.Spec.Namespace, metav1.GetOptions{})
	if err != nil {
		return err
	}
	target := TargetIdentity(e.Kube.Config.Host, string(ns.UID))
	if h.TargetID != target || h.NamespaceUID != string(ns.UID) {
		return spec.Err(11, "hardware evidence belongs to another target")
	}
	node, err := e.Kube.Client.CoreV1().Nodes().Get(ctx, h.NodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(node.UID) != h.NodeUID {
		return spec.Err(11, "hardware probe node was replaced")
	}
	if err := rejectSharedGPUNode(node); err != nil {
		return err
	}
	job, err := e.Kube.Client.BatchV1().Jobs(e.Site.Spec.Namespace).Get(ctx, h.JobName, metav1.GetOptions{})
	if err != nil {
		return spec.Err(10, "original hardware probe Job is unavailable")
	}
	if string(job.UID) != h.JobUID || job.Labels["cinderlock.dev/run"] != h.RunID || len(job.Spec.Template.Spec.Containers) != 1 {
		return spec.Err(12, "hardware evidence Job identity conflicts")
	}
	if job.Annotations["cinderlock.dev/node-uid"] != h.NodeUID || job.Status.CompletionTime == nil || !job.Status.CompletionTime.Time.Equal(observed) {
		return spec.Err(12, "hardware evidence node or observation time differs from original Job")
	}
	if job.Annotations["cinderlock.dev/bundle-digest"] != h.BundleDigest || job.Annotations["cinderlock.dev/profile"] != h.Profile {
		return spec.Err(12, "hardware evidence bundle/profile differs from original probe Job")
	}
	complete := false
	for _, condition := range job.Status.Conditions {
		if condition.Type == batchv1.JobComplete && condition.Status == corev1.ConditionTrue {
			complete = true
		}
	}
	if !complete {
		return spec.Err(10, "original hardware probe Job is not complete")
	}
	pod, err := e.Kube.Client.CoreV1().Pods(e.Site.Spec.Namespace).Get(ctx, h.PodName, metav1.GetOptions{})
	if err != nil {
		return spec.Err(10, "original hardware probe Pod is unavailable")
	}
	if string(pod.UID) != h.PodUID || pod.Spec.NodeName != h.NodeName || pod.Status.Phase != corev1.PodSucceeded || len(pod.Spec.Containers) != 1 {
		return spec.Err(12, "hardware evidence Pod identity conflicts")
	}
	owned := false
	for _, owner := range pod.OwnerReferences {
		if string(owner.UID) == h.JobUID && owner.Kind == "Job" {
			owned = true
		}
	}
	if !owned {
		return spec.Err(12, "hardware evidence Pod is not owned by its recorded Job")
	}
	c := pod.Spec.Containers[0]
	j := job.Spec.Template.Spec.Containers[0]
	if c.Image != h.ProbeImage || j.Image != h.ProbeImage || !slices.Equal(c.Command, gpuCommand) || !slices.Equal(c.Args, gpuArguments) || !slices.Equal(j.Command, gpuCommand) || !slices.Equal(j.Args, gpuArguments) {
		return spec.Err(12, "hardware probe image or fixed command changed")
	}
	count := int64(len(h.GPUs))
	request := c.Resources.Requests[corev1.ResourceName("nvidia.com/gpu")]
	limit := c.Resources.Limits[corev1.ResourceName("nvidia.com/gpu")]
	if count < 1 || request.Value() != count || limit.Value() != count {
		return spec.Err(12, "hardware probe device request conflicts with observations")
	}
	output, err := e.podLogs(ctx, h.PodName)
	if err != nil {
		return err
	}
	if spec.Hash(output) != h.OutputDigest {
		return spec.Err(12, "hardware probe output changed")
	}
	facts, err := ParseGPUFacts(output)
	if err != nil {
		return err
	}
	expected, _ := spec.Digest(struct {
		GPUs []GPUFact `json:"gpus"`
	}{h.GPUs})
	actual, _ := spec.Digest(struct {
		GPUs []GPUFact `json:"gpus"`
	}{facts})
	if expected != actual {
		return spec.Err(12, "hardware facts do not match original probe output")
	}
	if v != nil {
		profile := v.Index.Lock.Release.Spec.AIProfile
		if int64(len(facts)) < profile.GPUCount {
			return spec.Err(10, "observed device count below application profile")
		}
		for _, gpu := range facts {
			if len(profile.GPUModels) > 0 && !slices.Contains(profile.GPUModels, gpu.Model) {
				return spec.Err(10, "GPU model %s is outside supported profile", gpu.Model)
			}
			if gpu.MemoryMiB < profile.MinGPUMemoryMiB {
				return spec.Err(10, "GPU memory below supported profile")
			}
			if len(profile.DriverVersions) > 0 && !slices.Contains(profile.DriverVersions, gpu.DriverVersion) {
				return spec.Err(10, "GPU driver %s is outside supported profile", gpu.DriverVersion)
			}
		}
	}
	return nil
}

func rejectSharedGPUNode(node *corev1.Node) error {
	for _, key := range []string{"nvidia.com/gpu.sharing-strategy", "nvidia.com/mig.strategy"} {
		value := strings.ToLower(node.Labels[key])
		if value != "" && value != "none" {
			return spec.Err(10, "node advertises a shared/MIG GPU strategy requiring a separate qualified profile")
		}
	}
	return nil
}
