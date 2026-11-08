package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
)

func (e *Engine) addAdmissionFindings(ctx context.Context, p *spec.Plan, objects []map[string]any, policy spec.TrustPolicy) {
	if !p.Executable {
		return
	}
	findings := e.AdmissionFindings(ctx, *p, objects, policy)
	for _, finding := range findings {
		if finding.Severity == "blocker" {
			p.Executable = false
		}
	}
	p.Findings = append(p.Findings, findings...)
}

// AdmissionFindings makes explicitly enabled, nonpersistent API requests.
// Configured admission webhooks can run; their future decisions aren't certified.
func (e *Engine) AdmissionFindings(ctx context.Context, p spec.Plan, objects []map[string]any, policy spec.TrustPolicy) []spec.Finding {
	if !e.Site.Spec.AdmissionDryRun {
		return []spec.Finding{{Code: "ADMISSION_NOT_TESTED", Severity: "info", Message: "server admission dry-run was not enabled; future object and controller admission remains untested"}}
	}
	if !slices.Contains(e.Site.Spec.AllowedActions, "admission-dry-run") || !slices.Contains(policy.Spec.AllowedActions, "admission-dry-run") {
		return []spec.Finding{{Code: "ADMISSION_CAPABILITY_DENIED", Severity: "blocker", Message: "server admission requests require admission-dry-run in both Site and TrustPolicy"}}
	}
	if !slices.ContainsFunc(p.Operations, func(op spec.Operation) bool { return op.Type == "helm" }) {
		return []spec.Finding{{Code: "ADMISSION_NOT_APPLICABLE", Severity: "info", Message: "selected operations contain no Helm transition; helper Job admission is not covered by this check"}}
	}
	if len(objects) == 0 || len(objects) > 256 {
		return []spec.Finding{{Code: "ADMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "admission preflight requires a bounded validated Helm resource inventory"}}
	}
	client := e.DynamicClient
	if client == nil {
		var err error
		client, err = dynamic.NewForConfig(e.Kube.Config)
		if err != nil {
			return []spec.Finding{{Code: "ADMISSION_UNAVAILABLE", Severity: "blocker", Message: "target admission client is unavailable"}}
		}
	}
	previous := map[string]map[string]any{}
	if p.SourceVersion != "" {
		data, err := e.helm(ctx, "get", "manifest", e.Site.Spec.ReleaseName)
		if err != nil {
			return []spec.Finding{{Code: "ADMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "previous Helm manifest is unavailable for update admission"}}
		}
		inventory, err := PermissionObjects(data)
		if err != nil {
			return []spec.Finding{{Code: "ADMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "previous Helm inventory is invalid"}}
		}
		for _, o := range inventory {
			key, _, err := e.admissionObject(o)
			if err != nil || previous[key] != nil {
				return []spec.Finding{{Code: "ADMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "previous Helm inventory has ambiguous or unsupported resource identities"}}
			}
			previous[key] = o
		}
	}
	findings := []spec.Finding{{Code: "ADMISSION_SCOPE", Severity: "info", Message: "point-in-time server dry-run of submitted Helm objects only; configured webhooks can execute; controller-created Pods, helper Jobs, future admission, and resource availability are not verified", Source: "Kubernetes dryRun=All"}}
	seen := map[string]bool{}
	for _, raw := range objects {
		if ctx.Err() != nil {
			break
		}
		key, resource, err := e.admissionObject(raw)
		if err != nil || seen[key] {
			return append(findings, spec.Finding{Code: "ADMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "desired Helm resource identities are ambiguous or outside the supported namespace profile"})
		}
		seen[key] = true
		encoded, err := json.Marshal(raw)
		if err != nil {
			return append(findings, spec.Finding{Code: "ADMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "desired Helm object cannot be encoded"})
		}
		object := &unstructured.Unstructured{}
		if err = object.UnmarshalJSON(encoded); err != nil {
			return append(findings, spec.Finding{Code: "ADMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "desired Helm object is invalid"})
		}
		object.SetNamespace(e.Site.Spec.Namespace)
		labels, _, err := unstructured.NestedStringMap(object.Object, "metadata", "labels")
		if err != nil {
			return append(findings, spec.Finding{Code: "ADMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "rendered metadata labels must contain strings"})
		}
		if labels == nil {
			labels = map[string]string{}
		}
		labels["app.kubernetes.io/managed-by"] = "Helm"
		object.SetLabels(labels)
		annotations, _, err := unstructured.NestedStringMap(object.Object, "metadata", "annotations")
		if err != nil {
			return append(findings, spec.Finding{Code: "ADMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "rendered metadata annotations must contain strings"})
		}
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations["meta.helm.sh/release-name"] = e.Site.Spec.ReleaseName
		annotations["meta.helm.sh/release-namespace"] = e.Site.Spec.Namespace
		object.SetAnnotations(annotations)
		request, cancel := context.WithTimeout(ctx, 35*time.Second)
		api := client.Resource(resource).Namespace(e.Site.Spec.Namespace)
		current, getErr := api.Get(request, object.GetName(), metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			_, err = api.Create(request, object, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldManager: "cinderlock-preflight"})
		} else if getErr != nil || current == nil {
			err = getErr
			if err == nil {
				err = fmt.Errorf("empty current object")
			}
		} else if p.SourceVersion == "" || current.GetDeletionTimestamp() != nil || current.GetAnnotations()["meta.helm.sh/release-name"] != e.Site.Spec.ReleaseName || current.GetAnnotations()["meta.helm.sh/release-namespace"] != e.Site.Spec.Namespace {
			cancel()
			findings = append(findings, spec.Finding{Code: "ADMISSION_OWNERSHIP_CONFLICT", Severity: "blocker", Message: "existing " + key + " is not an active object of the selected Helm release"})
			continue
		} else if original := previous[key]; original == nil {
			cancel()
			findings = append(findings, spec.Finding{Code: "ADMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "existing " + key + " has no previous Helm render for a three-way update"})
			continue
		} else {
			var patch []byte
			patch, err = admissionPatch(original, object.Object, current.Object)
			if err == nil {
				_, err = api.Patch(request, object.GetName(), types.StrategicMergePatchType, patch, metav1.PatchOptions{DryRun: []string{metav1.DryRunAll}, FieldManager: "cinderlock-preflight"})
			}
		}
		cancel()
		finding := spec.Finding{Code: "ADMISSION_ACCEPTED", Severity: "info", Message: key + " passed this server dry-run", Source: "Kubernetes dryRun=All"}
		if err != nil {
			finding.Code, finding.Severity = "ADMISSION_UNAVAILABLE", "blocker"
			finding.Message = "server admission could not be established for " + key
			if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
				finding.Code = "ADMISSION_DENIED"
				finding.Message = "server authorization or admission denied " + key
			}
			if apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) || apierrors.IsConflict(err) {
				finding.Code = "ADMISSION_REJECTED"
				finding.Message = "server rejected the rendered object " + key
			}
		}
		findings = append(findings, finding)
	}
	if ctx.Err() != nil {
		findings = append(findings, spec.Finding{Code: "ADMISSION_INTERRUPTED", Severity: "blocker", Message: "server admission preflight was interrupted; complete inventory admission was not established"})
	}
	return findings
}

func (e *Engine) admissionObject(object map[string]any) (string, schema.GroupVersionResource, error) {
	u := &unstructured.Unstructured{Object: object}
	r, ok := permissionResources[u.GetKind()]
	if !ok || u.GetAPIVersion() != r.version || u.GetName() == "" || u.GetGenerateName() != "" || u.GetNamespace() != "" && u.GetNamespace() != e.Site.Spec.Namespace {
		return "", schema.GroupVersionResource{}, fmt.Errorf("unsupported resource identity")
	}
	v, err := schema.ParseGroupVersion(r.version)
	if err != nil {
		return "", schema.GroupVersionResource{}, err
	}
	return r.version + "/" + u.GetKind() + "/" + u.GetName(), schema.GroupVersionResource{Group: r.group, Version: v.Version, Resource: r.resource}, nil
}

func admissionPatch(original, desired, current map[string]any) ([]byte, error) {
	u := &unstructured.Unstructured{Object: desired}
	typed, err := scheme.Scheme.New(u.GroupVersionKind())
	if err != nil {
		return nil, err
	}
	meta, err := strategicpatch.NewPatchMetaFromStruct(typed)
	if err != nil {
		return nil, err
	}
	a, err := json.Marshal(original)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(desired)
	if err != nil {
		return nil, err
	}
	c, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	return strategicpatch.CreateThreeWayMergePatch(a, b, c, meta, true)
}
