package engine

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestGPUCSVRejectsUnknownsAndDuplicateDevices(t *testing.T) {
	facts, err := ParseGPUFacts([]byte("GPU-123, NVIDIA A100, 40960, 550.54.15, Disabled\n"))
	if err != nil || len(facts) != 1 || facts[0].MemoryMiB != 40960 {
		t.Fatalf("facts=%#v error=%v", facts, err)
	}
	for _, input := range []string{"GPU-123, NVIDIA A100, N/A, 550.54.15, Disabled\n", "MIG-123, NVIDIA A100, 40960, 550.54.15, Disabled\n", "GPU-123, NVIDIA A100, 40960, N/A, Disabled\n", "GPU-123, NVIDIA A100, 40960, 550.54.15, Disabled\nGPU-123, NVIDIA A100, 40960, 550.54.15, Disabled\n", "GPU-123, NVIDIA A100, 40960.5, 550.54.15, Disabled\n"} {
		if _, err := ParseGPUFacts([]byte(input)); err == nil {
			t.Fatalf("accepted ambiguous GPU evidence %q", input)
		}
	}
	if _, err := ParseGPUFacts([]byte("GPU-123, NVIDIA A100, 40960, 550.54.15, Enabled\n")); err == nil {
		t.Fatal("enabled MIG accepted as a full GPU profile")
	}
}

func hardwareFixture(t *testing.T) (*Engine, HardwareEvidence, *bundle.Verified) {
	t.Helper()
	e, client, policy := fixture(t)
	ctx := context.Background()
	p, v := fixturePlan(t, e, policy)
	output := []byte("GPU-123, NVIDIA A100, 40960, 550.54.15, Disabled\n")
	e.PodLogReader = func(context.Context, string) ([]byte, error) { return output, nil }
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "gpu-node", UID: types.UID("node-1")}, Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{corev1.ResourceName("nvidia.com/gpu"): resource.MustParse("1")}}}
	if _, err := client.CoreV1().Nodes().Create(ctx, node, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	image := "registry.invalid/probe@sha256:" + strings.Repeat("c", 64)
	quantity := resource.MustParse("1")
	container := corev1.Container{Name: "operation", Image: image, Command: slices.Clone(gpuCommand), Args: slices.Clone(gpuArguments), Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceName("nvidia.com/gpu"): quantity}, Limits: corev1.ResourceList{corev1.ResourceName("nvidia.com/gpu"): quantity}}}
	completed := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "gpu-job", Namespace: "test", UID: types.UID("job-1"), Labels: map[string]string{"cinderlock.dev/run": "probe-run"}, Annotations: map[string]string{"cinderlock.dev/node-uid": "node-1"}}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{container}}}}, Status: batchv1.JobStatus{CompletionTime: &completed, Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}}}
	job.Annotations["cinderlock.dev/bundle-digest"] = v.Digest
	job.Annotations["cinderlock.dev/profile"] = e.Site.Spec.Profile
	if _, err := client.BatchV1().Jobs("test").Create(ctx, job, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gpu-pod", Namespace: "test", UID: types.UID("pod-1"), OwnerReferences: []metav1.OwnerReference{{Kind: "Job", UID: job.UID}}}, Spec: corev1.PodSpec{NodeName: "gpu-node", Containers: []corev1.Container{container}}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}
	if _, err := client.CoreV1().Pods("test").Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	facts, _ := ParseGPUFacts(output)
	h := HardwareEvidence{Header: spec.NewHeader("HardwareEvidence"), RunID: "probe-run", TargetID: p.Snapshot.TargetID, NamespaceUID: p.Snapshot.NamespaceUID, BundleDigest: v.Digest, Profile: e.Site.Spec.Profile, ObservedAt: completed.Time.Format(time.RFC3339Nano), ExpiresAt: completed.Add(time.Hour).Format(time.RFC3339Nano), ProbeImage: image, NodeName: "gpu-node", NodeUID: "node-1", JobName: "gpu-job", JobUID: "job-1", PodName: "gpu-pod", PodUID: "pod-1", OutputDigest: spec.Hash(output), GPUs: facts}
	return e, h, v
}

func TestHardwareEvidenceRechecksRemoteFactsAndRejectsEditing(t *testing.T) {
	e, h, v := hardwareFixture(t)
	ctx := context.Background()
	if err := e.validateHardware(ctx, h, v); err != nil {
		t.Fatal(err)
	}
	h.GPUs[0].Model = "invented device"
	if err := e.validateHardware(ctx, h, v); spec.ExitCode(err) != 12 {
		t.Fatalf("locally edited hardware accepted: %v", err)
	}
}

func TestHardwareEvidenceRejectsReplacedNodeAndForgedTime(t *testing.T) {
	e, h, v := hardwareFixture(t)
	ctx := context.Background()
	original := h.ObservedAt
	h.ObservedAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	if err := e.validateHardware(ctx, h, v); spec.ExitCode(err) != 12 {
		t.Fatalf("changed original observation time accepted: %v", err)
	}
	h.ObservedAt = original
	if err := e.Kube.Client.CoreV1().Nodes().Delete(ctx, "gpu-node", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := e.Kube.Client.CoreV1().Nodes().Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "gpu-node", UID: types.UID("node-2")}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.validateHardware(ctx, h, v); spec.ExitCode(err) != 11 {
		t.Fatalf("replacement node accepted: %v", err)
	}
	h.NodeUID = "node-2"
	if err := e.validateHardware(ctx, h, v); spec.ExitCode(err) != 12 {
		t.Fatalf("changed local node UID bypassed original Job binding: %v", err)
	}
}

func TestRegistryCredentialsAreScopedAndHelpersNeverRun(t *testing.T) {
	e, _, _ := fixture(t)
	path := filepath.Join(t.TempDir(), "docker.json")
	e.Site.Spec.Registry = "registry.internal/project"
	e.Site.Spec.RegistryAuthRef = "registry"
	e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"registry": {File: path}}
	encoded := base64.StdEncoding.EncodeToString([]byte("operator:private-password"))
	if err := os.WriteFile(path, []byte(`{"auths":{"registry.internal":{"auth":"`+encoded+`"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	opts, err := e.registryOptions(context.Background())
	if err != nil || opts.Username != "operator" || opts.Password != "private-password" {
		t.Fatalf("registry credential resolution failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"auths":{},"credsStore":"must-not-run"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.registryOptions(context.Background()); err == nil {
		t.Fatal("unqualified credential helper accepted")
	}
	if err := os.WriteFile(path, []byte(`{"auths":{"other.internal":{"auth":"`+encoded+`"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.registryOptions(context.Background()); spec.ExitCode(err) != 10 {
		t.Fatalf("credential applied to another registry: %v", err)
	}
}

func TestProbePlanningIsReadOnlyAndCommandScopeCannotChange(t *testing.T) {
	e, client, policy := fixture(t)
	e.Site.Spec.Registry = "registry.internal"
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "probe")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "probe")
	policy.Spec.Epoch++
	admitFixturePolicy(t, e, policy)
	p, v := fixturePlan(t, e, policy)
	v.Index.Lock.Assets = []spec.LockedAsset{{ID: "runner", Type: "image", Source: "registry.invalid/runner:1", Digest: "sha256:" + strings.Repeat("c", 64)}}
	_, err := client.CoreV1().Nodes().Create(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "gpu-node", UID: "node-1"}, Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{corev1.ResourceName("nvidia.com/gpu"): resource.MustParse("1")}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	before := len(client.Actions())
	probe, err := e.ProbePlan(context.Background(), v, p.BundlePath, p.SitePath, policy, "runner", "gpu-node")
	if err != nil {
		t.Fatal(err)
	}
	if !probe.Executable {
		t.Fatalf("explicitly enrolled probe profile blocked: %#v", probe.Findings)
	}
	for _, action := range client.Actions()[before:] {
		if action.GetVerb() != "get" && action.GetVerb() != "list" && !(action.GetVerb() == "create" && action.GetResource().Resource == "selfsubjectaccessreviews") {
			t.Fatalf("probe planning mutated target: %s", action.GetVerb())
		}
	}
	if err := e.verifyProbeBinding(probe, v); err != nil {
		t.Fatal(err)
	}
	probe.Operations[1].Command = []string{"/bin/sh"}
	if err := e.verifyProbeBinding(probe, v); spec.ExitCode(err) != 12 {
		t.Fatalf("changed probe command accepted: %v", err)
	}
}
