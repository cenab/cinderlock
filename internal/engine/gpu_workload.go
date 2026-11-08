package engine

import (
	"context"
	"fmt"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func needsHardware(profile spec.AIProfile) bool {
	return profile.GPUCount > 0 || len(profile.GPUModels) > 0 || profile.MinGPUMemoryMiB > 0 || len(profile.DriverVersions) > 0
}

func (e *Engine) inspectGPUWorkloads(ctx context.Context, objects []map[string]any, v *bundle.Verified) error {
	profile := v.Index.Lock.Release.Spec.AIProfile
	if !needsHardware(profile) {
		return nil
	}
	var hardware HardwareEvidence
	if err := spec.Read(e.Site.Spec.HardwareEvidence, &hardware); err != nil {
		return err
	}
	if profile.RuntimeAsset == "" {
		return spec.Err(10, "GPU profile must identify the exact inference runtime image asset")
	}
	runtime, err := e.image(v, profile.RuntimeAsset)
	if err != nil {
		return err
	}
	minimum := profile.GPUCount
	if minimum < 1 {
		minimum = 1
	}
	found := false
	for _, object := range objects {
		kind, _ := object["kind"].(string)
		if kind != "Deployment" && kind != "StatefulSet" {
			continue
		}
		body, _ := object["spec"].(map[string]any)
		template, _ := body["template"].(map[string]any)
		pod, _ := template["spec"].(map[string]any)
		containers, _ := pod["containers"].([]any)
		for _, value := range containers {
			container, _ := value.(map[string]any)
			if container["image"] != runtime {
				continue
			}
			found = true
			resources, _ := container["resources"].(map[string]any)
			limits, _ := resources["limits"].(map[string]any)
			q, err := resource.ParseQuantity(fmt.Sprint(limits["nvidia.com/gpu"]))
			if err != nil || q.Value() < minimum || q.Value() > int64(len(hardware.GPUs)) {
				return spec.Err(10, "runtime GPU limit does not match the probed full-GPU profile")
			}
			if !e.podBoundToHardwareNode(ctx, pod, hardware) {
				return spec.Err(10, "GPU runtime must be constrained to its probed node through nodeName, exact required node affinity, or a uniquely matched nodeSelector")
			}
		}
	}
	if !found {
		return spec.Err(10, "rendered chart has no workload using the declared GPU runtime image")
	}
	return nil
}

func (e *Engine) podBoundToHardwareNode(ctx context.Context, pod map[string]any, h HardwareEvidence) bool {
	if name, _ := pod["nodeName"].(string); name != "" {
		return name == h.NodeName
	}
	if selector, ok := pod["nodeSelector"].(map[string]any); ok && len(selector) > 0 {
		values := map[string]string{}
		for key, value := range selector {
			text, ok := value.(string)
			if !ok {
				return false
			}
			values[key] = text
		}
		nodes, err := e.Kube.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromSet(values).String()})
		if err == nil && len(nodes.Items) == 1 && nodes.Items[0].Name == h.NodeName && string(nodes.Items[0].UID) == h.NodeUID {
			return true
		}
	}
	affinity, _ := pod["affinity"].(map[string]any)
	nodeAffinity, _ := affinity["nodeAffinity"].(map[string]any)
	required, _ := nodeAffinity["requiredDuringSchedulingIgnoredDuringExecution"].(map[string]any)
	terms, _ := required["nodeSelectorTerms"].([]any)
	if len(terms) == 0 {
		return false
	}
	for _, value := range terms {
		term, _ := value.(map[string]any)
		fields, _ := term["matchFields"].([]any)
		constrained := false
		for _, value := range fields {
			field, _ := value.(map[string]any)
			values, _ := field["values"].([]any)
			if field["key"] == "metadata.name" && field["operator"] == "In" && len(values) == 1 && values[0] == h.NodeName {
				constrained = true
			}
		}
		if !constrained {
			return false
		}
	}
	return true
}

func (e *Engine) verifyGPUAssignment(ctx context.Context, v *bundle.Verified) error {
	profile := v.Index.Lock.Release.Spec.AIProfile
	if !needsHardware(profile) {
		return nil
	}
	var h HardwareEvidence
	if err := spec.Read(e.Site.Spec.HardwareEvidence, &h); err != nil {
		return err
	}
	if err := e.validateHardware(ctx, h, v); err != nil {
		return err
	}
	image, err := e.image(v, profile.RuntimeAsset)
	if err != nil {
		return err
	}
	pods, err := e.Kube.Client.CoreV1().Pods(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/instance=" + e.Site.Spec.ReleaseName})
	if err != nil {
		return err
	}
	found := false
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if container.Image != image {
				continue
			}
			found = true
			if pod.Spec.NodeName != h.NodeName || pod.Status.Phase != corev1.PodRunning {
				return spec.Err(10, "runtime Pod is not running on the probed hardware node")
			}
			node, err := e.Kube.Client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if string(node.UID) != h.NodeUID {
				return spec.Err(11, "runtime node identity changed after hardware probe")
			}
			limit := container.Resources.Limits[corev1.ResourceName("nvidia.com/gpu")]
			minimum := profile.GPUCount
			if minimum < 1 {
				minimum = 1
			}
			if limit.Value() < minimum || limit.Value() > int64(len(h.GPUs)) {
				return spec.Err(10, "actual runtime Pod GPU request is outside probed capacity")
			}
		}
	}
	if !found {
		return spec.Err(10, "no runtime Pod observation matched the GPU profile")
	}
	return nil
}
