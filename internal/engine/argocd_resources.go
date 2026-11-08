package engine

import (
	"bytes"
	"encoding/json"
	"net"
	"reflect"
	"slices"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/applyconfigurations"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/structured-merge-diff/v6/fieldpath"
)

func (e *Engine) gitOpsProfileInventory(manifest []byte, c GitOpsProfileContract) ([]*unstructured.Unstructured, error) {
	objects, err := PermissionObjects(manifest)
	if err != nil || len(objects) == 0 || len(objects) > 64 {
		return nil, spec.Err(2, "GitOps profile requires one to 64 unambiguous reviewed resources")
	}
	seen := map[string]bool{}
	out := make([]*unstructured.Unstructured, 0, len(objects))
	for _, raw := range objects {
		body, err := json.Marshal(raw)
		u := &unstructured.Unstructured{}
		if err != nil || u.UnmarshalJSON(body) != nil {
			return nil, spec.Err(2, "GitOps reviewed resource is malformed")
		}
		key, _, err := e.admissionObject(u.Object)
		if err != nil || seen[key] || !slices.Contains([]string{"Deployment", "Service", "ConfigMap"}, u.GetKind()) || len(validation.IsDNS1123Subdomain(u.GetName())) != 0 {
			return nil, spec.Err(2, "GitOps reviewed inventory contains an unsupported or ambiguous resource identity")
		}
		seen[key] = true
		u.SetNamespace(e.Site.Spec.Namespace)
		metadata, _ := u.Object["metadata"].(map[string]any)
		if _, exists := u.Object["status"]; exists {
			return nil, spec.Err(2, "GitOps reviewed resources cannot supply producer status")
		}
		if !gitOpsProfileKeys(metadata, "name", "namespace", "labels", "annotations") || !gitOpsProfileMetadata(u, c, false) || !gitOpsProfileShape(u) {
			return nil, spec.Err(2, "GitOps reviewed resource contains unsupported ownership or execution behavior")
		}
		out = append(out, u)
	}
	return out, nil
}

func gitOpsProfileMetadata(u *unstructured.Unstructured, c GitOpsProfileContract, trackingRequired bool) bool {
	for _, field := range []string{"ownerReferences", "finalizers"} {
		v, found, err := unstructured.NestedSlice(u.Object, "metadata", field)
		if err != nil || found && len(v) != 0 {
			return false
		}
	}
	labels, _, labelErr := unstructured.NestedStringMap(u.Object, "metadata", "labels")
	annotations, _, annotationErr := unstructured.NestedStringMap(u.Object, "metadata", "annotations")
	if labelErr != nil || annotationErr != nil {
		return false
	}
	group := u.GroupVersionKind().Group
	expected := c.Name + ":" + group + "/" + u.GetKind() + ":" + u.GetNamespace() + "/" + u.GetName()
	if trackingRequired && annotations["argocd.argoproj.io/tracking-id"] != expected {
		return false
	}
	if trackingRequired && annotations["argocd.argoproj.io/installation-id"] != c.InstallationID {
		return false
	}
	for _, entries := range []map[string]string{labels, annotations} {
		for key, value := range entries {
			if strings.HasPrefix(key, "meta.helm.sh/") || strings.HasPrefix(key, "helm.sh/") && key != "helm.sh/chart" || strings.HasPrefix(key, "helm.toolkit.fluxcd.io/") || strings.HasPrefix(key, "kustomize.toolkit.fluxcd.io/") || strings.HasPrefix(key, "toolkit.fluxcd.io/") || strings.HasPrefix(key, "fluxcd.io/") || key == "app.kubernetes.io/managed-by" && strings.Contains(strings.ToLower(value), "flux") {
				return false
			}
			if !strings.HasPrefix(key, "argocd.argoproj.io/") {
				continue
			}
			switch key {
			case "argocd.argoproj.io/tracking-id":
				if value != expected {
					return false
				}
			case "argocd.argoproj.io/installation-id":
				if value != c.InstallationID {
					return false
				}
			case "argocd.argoproj.io/instance":
				if value != c.Name {
					return false
				}
			case "argocd.argoproj.io/sync-wave":
				if value != "0" {
					return false
				}
			case "argocd.argoproj.io/sync-options":
				var options []any
				for _, option := range strings.Split(value, ",") {
					options = append(options, strings.TrimSpace(option))
				}
				if !gitOpsProfileOptions(options) {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

func gitOpsProfileShape(u *unstructured.Unstructured) bool {
	var typed any
	switch u.GetKind() {
	case "Deployment":
		typed = &appsv1.Deployment{}
	case "Service":
		typed = &corev1.Service{}
	case "ConfigMap":
		typed = &corev1.ConfigMap{}
	default:
		return false
	}
	if runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(u.Object, typed, true) != nil {
		return false
	}
	switch u.GetKind() {
	case "Deployment":
		if !gitOpsProfileKeys(u.Object, "apiVersion", "kind", "metadata", "spec", "status") {
			return false
		}
		selector, found, err := unstructured.NestedMap(u.Object, "spec", "selector")
		if err != nil || !found || len(selector) == 0 {
			return false
		}
		pod, found, err := unstructured.NestedMap(u.Object, "spec", "template", "spec")
		if err != nil || !found {
			return false
		}
		for _, key := range []string{"initContainers", "ephemeralContainers"} {
			if value, exists := pod[key]; exists {
				list, ok := value.([]any)
				if !ok || len(list) != 0 {
					return false
				}
			}
		}
		containers, ok := pod["containers"].([]any)
		if !ok || len(containers) == 0 {
			return false
		}
		for _, value := range containers {
			container, ok := value.(map[string]any)
			if !ok {
				return false
			}
			if _, exists := container["lifecycle"]; exists {
				return false
			}
		}
		template, _, _ := unstructured.NestedMap(u.Object, "spec", "template", "metadata")
		// Pod-template markers must not hide a second hook or ownership configuration.
		if template != nil {
			p := &unstructured.Unstructured{Object: map[string]any{"metadata": template}}
			if !gitOpsProfileMetadata(p, GitOpsProfileContract{}, false) {
				return false
			}
		}
		return true
	case "Service":
		if !gitOpsProfileKeys(u.Object, "apiVersion", "kind", "metadata", "spec", "status") {
			return false
		}
		s, found, err := unstructured.NestedMap(u.Object, "spec")
		if err != nil || !found {
			return false
		}
		if serviceType, exists := s["type"]; exists && serviceType != "ClusterIP" {
			return false
		}
		for _, key := range []string{"externalName", "loadBalancerIP", "loadBalancerClass", "externalTrafficPolicy"} {
			if value, exists := s[key]; exists && value != "" && value != nil {
				return false
			}
		}
		if value, exists := s["externalIPs"]; exists {
			if list, ok := value.([]any); !ok || len(list) != 0 {
				return false
			}
		}
		if value, exists := s["healthCheckNodePort"]; exists && value != int64(0) {
			return false
		}
		if _, exists := s["allocateLoadBalancerNodePorts"]; exists {
			return false
		}
		selector, ok := s["selector"].(map[string]any)
		if !ok || len(selector) == 0 {
			return false
		}
		ports, ok := s["ports"].([]any)
		if !ok || len(ports) == 0 {
			return false
		}
		for _, value := range ports {
			port, ok := value.(map[string]any)
			if !ok {
				return false
			}
			if value, exists := port["nodePort"]; exists && value != int64(0) {
				return false
			}
		}
		return true
	case "ConfigMap":
		if !gitOpsProfileKeys(u.Object, "apiVersion", "kind", "metadata", "data", "binaryData", "immutable") {
			return false
		}
		for _, key := range []string{"data", "binaryData"} {
			if _, _, err := unstructured.NestedStringMap(u.Object, key); err != nil {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func gitOpsProfileSuppliedMatch(desired, live any) bool {
	switch d := desired.(type) {
	case map[string]any:
		current, ok := live.(map[string]any)
		if !ok {
			return false
		}
		for key, value := range d {
			actual, exists := current[key]
			if !exists || !gitOpsProfileSuppliedMatch(value, actual) {
				return false
			}
		}
		return true
	case []any:
		current, ok := live.([]any)
		if !ok || len(d) != len(current) {
			return false
		}
		for i, value := range d {
			if !gitOpsProfileSuppliedMatch(value, current[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(desired, live)
	}
}

func gitOpsProfileFieldsMatch(desired, live map[string]any) bool {
	if !gitOpsProfileSuppliedMatch(desired, live) {
		return false
	}
	if desired["kind"] == "ConfigMap" {
		immutableOK := true
		if _, supplied := desired["immutable"]; !supplied {
			value, exists := live["immutable"]
			immutableOK = !exists || value == false
		}
		return immutableOK && reflect.DeepEqual(desired["data"], live["data"]) && reflect.DeepEqual(desired["binaryData"], live["binaryData"])
	}
	d, _, dErr := unstructured.NestedMap(desired, "spec", "selector")
	l, _, lErr := unstructured.NestedMap(live, "spec", "selector")
	return dErr == nil && lErr == nil && reflect.DeepEqual(d, l) && gitOpsProfileDefaultExtras(desired["spec"], live["spec"], desired["kind"].(string)+".spec")
}

// Only known API defaults may add spec map keys; lists still retain exact length and order.
func gitOpsProfileDefaultExtras(desired, live any, field string) bool {
	switch d := desired.(type) {
	case map[string]any:
		current, ok := live.(map[string]any)
		if !ok {
			return false
		}
		for key, value := range current {
			if wanted, supplied := d[key]; supplied {
				if !gitOpsProfileDefaultExtras(wanted, value, field+"."+key) {
					return false
				}
			} else if !gitOpsProfileDefault(field, key, value, current) {
				return false
			}
		}
	case []any:
		current, ok := live.([]any)
		if !ok || len(d) != len(current) {
			return false
		}
		for i, wanted := range d {
			if !gitOpsProfileDefaultExtras(wanted, current[i], field+"[]") {
				return false
			}
		}
	}
	return true
}

func gitOpsProfileDefault(field, key string, value any, siblings map[string]any) bool {
	var defaults map[string]any
	switch field {
	case "Deployment.spec":
		defaults = map[string]any{"replicas": int64(1), "revisionHistoryLimit": int64(10), "progressDeadlineSeconds": int64(600)}
		if key == "strategy" {
			return gitOpsProfileDefaultExtras(map[string]any{}, value, field+".strategy")
		}
	case "Deployment.spec.strategy":
		defaults = map[string]any{"type": "RollingUpdate"}
		if key == "rollingUpdate" {
			return gitOpsProfileDefaultExtras(map[string]any{}, value, field+".rollingUpdate")
		}
	case "Deployment.spec.strategy.rollingUpdate":
		defaults = map[string]any{"maxSurge": "25%", "maxUnavailable": "25%"}
	case "Deployment.spec.template.metadata":
		defaults = map[string]any{"creationTimestamp": nil}
	case "Deployment.spec.template.spec":
		defaults = map[string]any{"restartPolicy": "Always", "dnsPolicy": "ClusterFirst", "schedulerName": "default-scheduler", "terminationGracePeriodSeconds": int64(30), "securityContext": map[string]any{}, "enableServiceLinks": true}
	case "Deployment.spec.template.spec.containers[]":
		defaults = map[string]any{"imagePullPolicy": "IfNotPresent", "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "resources": map[string]any{}}
	case "Deployment.spec.template.spec.containers[].ports[]":
		defaults = map[string]any{"protocol": "TCP"}
	case "Service.spec":
		defaults = map[string]any{"type": "ClusterIP", "sessionAffinity": "None", "internalTrafficPolicy": "Cluster", "ipFamilyPolicy": "SingleStack"}
		if key == "clusterIP" {
			text, ok := value.(string)
			return ok && net.ParseIP(text) != nil
		}
		if key == "clusterIPs" || key == "ipFamilies" {
			items, ok := value.([]any)
			if !ok || len(items) == 0 || len(items) > 2 {
				return false
			}
			for _, v := range items {
				text, ok := v.(string)
				if !ok {
					return false
				}
				if key == "clusterIPs" && net.ParseIP(text) == nil && !(text == "None" && siblings["clusterIP"] == "None" && len(items) == 1) || key == "ipFamilies" && text != "IPv4" && text != "IPv6" {
					return false
				}
			}
			return true
		}
	case "Service.spec.ports[]":
		defaults = map[string]any{"protocol": "TCP", "targetPort": siblings["port"], "nodePort": int64(0)}
	default:
		if strings.HasSuffix(field, ".livenessProbe") || strings.HasSuffix(field, ".readinessProbe") || strings.HasSuffix(field, ".startupProbe") {
			defaults = map[string]any{"initialDelaySeconds": int64(0), "timeoutSeconds": int64(1), "periodSeconds": int64(10), "successThreshold": int64(1), "failureThreshold": int64(3)}
		}
		if strings.HasSuffix(field, ".httpGet") {
			defaults = map[string]any{"path": "/", "scheme": "HTTP"}
		}
	}
	expected, known := defaults[key]
	return known && reflect.DeepEqual(value, expected)
}

func gitOpsProfileLiveHealth(live *unstructured.Unstructured) bool {
	if !gitOpsProfileShape(live) {
		return false
	}
	if live.GetKind() == "Service" {
		serviceType, found, err := unstructured.NestedString(live.Object, "spec", "type")
		return err == nil && found && serviceType == "ClusterIP"
	}
	if live.GetKind() != "Deployment" {
		return true
	}
	var deployment appsv1.Deployment
	return live.GetGeneration() > 0 && runtime.DefaultUnstructuredConverter.FromUnstructured(live.Object, &deployment) == nil && deploymentRolledOut(&deployment)
}

func gitOpsProfileManagedFields(desired, live *unstructured.Unstructured) bool {
	entries, found, err := unstructured.NestedSlice(live.Object, "metadata", "managedFields")
	if err != nil || !found || len(entries) == 0 || len(entries) > 64 {
		return false
	}
	relevant := map[string]any{}
	for _, key := range []string{"spec", "data", "binaryData", "immutable"} {
		if value, exists := desired.Object[key]; exists {
			relevant[key] = value
		}
	}
	metadata := map[string]any{}
	for _, key := range []string{"labels", "annotations"} {
		value, _, err := unstructured.NestedMap(desired.Object, "metadata", key)
		if err != nil {
			return false
		}
		if value == nil {
			value = map[string]any{}
		}
		current, _, err := unstructured.NestedMap(live.Object, "metadata", key)
		if err != nil {
			return false
		}
		for k, v := range current {
			if strings.HasPrefix(k, "argocd.argoproj.io/") {
				value[k] = v
			}
		}
		if len(value) > 0 {
			metadata[key] = value
		}
	}
	relevant["metadata"] = metadata
	// Use Kubernetes' schema to retain defaulted associative-list keys and the
	// distinction between map membership and ownership of a map's children.
	relevant["apiVersion"], relevant["kind"] = desired.GetAPIVersion(), desired.GetKind()
	typed, err := gitOpsFieldConverter.ObjectToTyped(&unstructured.Unstructured{Object: relevant})
	if err != nil {
		return false
	}
	required, err := typed.ToFieldSet()
	if err != nil {
		return false
	}
	required = required.Difference(fieldpath.NewSet(fieldpath.MakePathOrDie("apiVersion"), fieldpath.MakePathOrDie("kind"))).Leaves()
	owned := &fieldpath.Set{}
	seen := map[string]bool{}
	for _, value := range entries {
		entry, ok := value.(map[string]any)
		if !ok || !gitOpsProfileKeys(entry, "manager", "operation", "apiVersion", "time", "fieldsType", "fieldsV1", "subresource") || entry["fieldsType"] != "FieldsV1" || entry["apiVersion"] != live.GetAPIVersion() {
			return false
		}
		manager, ok := entry["manager"].(string)
		if !ok || manager == "" || (entry["operation"] != "Apply" && entry["operation"] != "Update") {
			return false
		}
		raw, ok := entry["fieldsV1"].(map[string]any)
		encoded, encodeErr := json.Marshal(raw)
		fields := &fieldpath.Set{}
		if !ok || encodeErr != nil || len(encoded) > 64<<10 || !gitOpsFieldEncoding(raw, 0) || fields.FromJSON(bytes.NewReader(encoded)) != nil || fields.Empty() {
			return false
		}
		sub, _ := entry["subresource"].(string)
		if v, exists := entry["subresource"]; exists && v != "" && v != "status" {
			return false
		}
		identity := manager + "/" + entry["operation"].(string) + "/" + sub
		if seen[identity] {
			return false
		}
		seen[identity] = true
		if sub == "status" {
			if !gitOpsProfileKeys(raw, "f:status") {
				return false
			}
			continue
		}
		fields = fields.Leaves()
		if manager == "argocd-controller" && entry["operation"] == "Apply" {
			owned = owned.Union(fields)
			continue
		}
		if !required.Intersection(fields).Empty() {
			return false
		}
	}
	// The schema already represents atomic fields as leaves. Granular parent
	// membership must never cover absent child claims.
	return !owned.Empty() && required.Difference(owned).Empty()
}

var gitOpsFieldConverter = applyconfigurations.NewTypeConverter(scheme.Scheme)

// The upstream reader skips unknown future path types; this profile fails closed.
func gitOpsFieldEncoding(fields map[string]any, depth int) bool {
	if depth > 64 || len(fields) > 4096 {
		return false
	}
	for key, value := range fields {
		child, ok := value.(map[string]any)
		if !ok || !gitOpsFieldEncoding(child, depth+1) {
			return false
		}
		if key == "." {
			if len(child) != 0 {
				return false
			}
			continue
		}
		path, err := fieldpath.DeserializePathElement(key)
		if err != nil || path.FieldName != nil && *path.FieldName == "" || path.Key != nil && len(*path.Key) == 0 || path.Index != nil && *path.Index < 0 {
			return false
		}
	}
	return true
}
