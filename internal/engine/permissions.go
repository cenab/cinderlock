package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"gopkg.in/yaml.v3"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type permissionResource struct {
	version, group, resource string
}

var permissionResources = map[string]permissionResource{
	"Deployment":            {"apps/v1", "apps", "deployments"},
	"StatefulSet":           {"apps/v1", "apps", "statefulsets"},
	"Service":               {"v1", "", "services"},
	"ConfigMap":             {"v1", "", "configmaps"},
	"Secret":                {"v1", "", "secrets"},
	"PersistentVolumeClaim": {"v1", "", "persistentvolumeclaims"},
	"ServiceAccount":        {"v1", "", "serviceaccounts"},
	"Role":                  {"rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io", "roles"},
	"RoleBinding":           {"rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io", "rolebindings"},
	"NetworkPolicy":         {"networking.k8s.io/v1", "networking.k8s.io", "networkpolicies"},
	"PodDisruptionBudget":   {"policy/v1", "policy", "poddisruptionbudgets"},
}

// PermissionFindings queries the current kubeconfig identity. Authorization
// reviews are nonpersistent requests; this never creates application resources.
func (e *Engine) PermissionFindings(ctx context.Context, p spec.Plan, objects []map[string]any) []spec.Finding {
	var previous []map[string]any
	for _, operation := range p.Operations {
		if operation.Type != "helm" || p.SourceVersion == "" {
			continue
		}
		data, err := e.helm(ctx, "get", "manifest", e.Site.Spec.ReleaseName)
		if err != nil {
			return []spec.Finding{{Code: "PERMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "installed Helm inventory is unavailable for removed-object permission planning"}}
		}
		previous, err = PermissionObjects(data)
		if err != nil || len(previous) == 0 {
			return []spec.Finding{{Code: "PERMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: "installed Helm inventory cannot establish removed-object permission scope"}}
		}
		break
	}
	requirements, err := e.permissionRequirements(p, objects, previous)
	if err != nil {
		return []spec.Finding{{Code: "PERMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: err.Error()}}
	}
	steps, err := e.permissionSteps(p, objects, previous)
	if err != nil {
		return []spec.Finding{{Code: "PERMISSION_SCOPE_UNAVAILABLE", Severity: "blocker", Message: err.Error()}}
	}
	findings := []spec.Finding{{Code: "PERMISSION_SCOPE", Severity: "info", Message: "authorization of the selected kubeconfig identity at query time only; each step includes the common target observer and coordination scope; admission, quotas, future permission changes, and workload service-account grants are unverified", Source: "authorization.k8s.io/v1 SelfSubjectAccessReview"}}
	findings = append(findings, steps...)
	for _, attributes := range requirements {
		if ctx.Err() != nil {
			return append(findings, spec.Finding{Code: "PERMISSION_UNAVAILABLE", Severity: "blocker", Message: "authorization preflight was interrupted before all requirements were evaluated"})
		}
		request, cancel := context.WithTimeout(ctx, 5*time.Second)
		review, reviewErr := e.Kube.Client.AuthorizationV1().SelfSubjectAccessReviews().Create(request, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &attributes}}, metav1.CreateOptions{})
		cancel()
		label := permissionLabel(attributes)
		finding := spec.Finding{Code: "PERMISSION_ALLOWED", Severity: "info", Message: label + " is currently allowed", Source: "authorization.k8s.io/v1 SelfSubjectAccessReview"}
		if reviewErr != nil || review == nil || review.Status.EvaluationError != "" || (!review.Status.Allowed && !review.Status.Denied) {
			finding.Code, finding.Severity, finding.Message = "PERMISSION_UNAVAILABLE", "blocker", label+" could not be conclusively evaluated"
		} else if !review.Status.Allowed || review.Status.Denied {
			finding.Code, finding.Severity, finding.Message = "PERMISSION_DENIED", "blocker", label+" is denied"
		}
		findings = append(findings, finding)
	}
	return findings
}

func (e *Engine) permissionSteps(p spec.Plan, objects, previous []map[string]any) ([]spec.Finding, error) {
	common, err := e.permissionRequirements(spec.Plan{}, nil, nil)
	if err != nil {
		return nil, err
	}
	shared := map[string]bool{}
	findings := []spec.Finding{}
	for _, attributes := range common {
		label := permissionLabel(attributes)
		shared[label] = true
		findings = append(findings, spec.Finding{Code: "PERMISSION_REQUIRED", Severity: "info", Message: "Kubernetes API caller requires " + label, Source: "target"})
	}
	disclose := func(step string, selected spec.Plan) error {
		requirements, err := e.permissionRequirements(selected, objects, previous)
		if err != nil {
			return err
		}
		for _, attributes := range requirements {
			label := permissionLabel(attributes)
			if !shared[label] {
				findings = append(findings, spec.Finding{Code: "PERMISSION_REQUIRED", Severity: "info", Message: "Kubernetes API caller requires " + label, Source: step})
			}
		}
		return nil
	}
	capability := func(step, action string) {
		findings = append(findings, spec.Finding{Code: "CAPABILITY_REQUIRED", Severity: "info", Message: "requires Site and TrustPolicy action " + action, Source: step})
	}
	worker := func(step string) {
		findings = append(findings, spec.Finding{Code: "SERVICE_ACCOUNT_REQUIRED", Severity: "info", Message: "Cinderlock worker uses ServiceAccount " + e.Site.Spec.Namespace + "/default; automountServiceAccountToken=false; service-account API grants are unverified", Source: step})
	}
	for _, op := range p.Operations {
		step := "operation/" + op.ID
		if err := disclose(step, spec.Plan{SourceVersion: p.SourceVersion, Operations: []spec.Operation{op}}); err != nil {
			return nil, err
		}
		capability(step, op.Type)
		if op.Type == "import" && e.Site.Spec.RegistryPlainHTTP {
			capability(step, "registry-http")
		}
		if jobOperation(op.Type) {
			worker(step)
		}
		if op.Type != "helm" {
			continue
		}
		if e.Site.Spec.AdmissionDryRun {
			capability(step, "admission-dry-run")
		}
		for _, object := range objects {
			kind, _ := object["kind"].(string)
			if kind != "Deployment" && kind != "StatefulSet" {
				continue
			}
			metadata, _ := object["metadata"].(map[string]any)
			name, _ := metadata["name"].(string)
			workload, _ := object["spec"].(map[string]any)
			template, _ := workload["template"].(map[string]any)
			pod, _ := template["spec"].(map[string]any)
			account, _ := pod["serviceAccountName"].(string)
			if account == "" {
				account, _ = pod["serviceAccount"].(string)
			}
			if account == "" {
				account = "default"
			}
			token := "unspecified; account and admission defaults unverified"
			if mount, ok := pod["automountServiceAccountToken"].(bool); ok {
				token = fmt.Sprint(mount)
			}
			findings = append(findings, spec.Finding{Code: "SERVICE_ACCOUNT_REQUIRED", Severity: "info", Message: kind + "/" + name + " uses ServiceAccount " + e.Site.Spec.Namespace + "/" + account + "; Pod automountServiceAccountToken=" + token + "; service-account API grants are unverified", Source: step})
		}
	}
	for _, check := range p.Checks {
		step := "check/" + check.ID
		if err := disclose(step, spec.Plan{Checks: []spec.Check{check}}); err != nil {
			return nil, err
		}
		capability(step, "job")
		worker(step)
	}
	return findings, nil
}

func permissionLabel(a authorizationv1.ResourceAttributes) string {
	scope := "namespace=" + a.Namespace
	if a.Namespace == "" {
		scope = "cluster-scoped"
	}
	resource := a.Resource
	if a.Group != "" {
		resource += "." + a.Group
	}
	if a.Subresource != "" {
		resource += "/" + a.Subresource
	}
	if a.Name != "" {
		resource += "/" + a.Name
	}
	return a.Verb + " " + resource + " (" + scope + ")"
}

func (e *Engine) permissionRequirements(p spec.Plan, objects, previous []map[string]any) ([]authorizationv1.ResourceAttributes, error) {
	namespace := e.Site.Spec.Namespace
	if namespace == "" || e.Kube == nil || e.Kube.Client == nil || (e.Kube.Namespace != "" && e.Kube.Namespace != namespace) {
		return nil, spec.Err(16, "authorization preflight requires one explicit matching target namespace")
	}
	required := map[string]authorizationv1.ResourceAttributes{}
	add := func(group, resource, name string, verbs ...string) {
		for _, verb := range verbs {
			a := authorizationv1.ResourceAttributes{Namespace: namespace, Group: group, Resource: resource, Name: name, Verb: verb}
			if verb == "create" {
				a.Name = ""
			}
			required[permissionLabel(a)] = a
		}
	}
	addSecrets := func(refs []string) error {
		for _, id := range refs {
			ref, ok := e.Site.Spec.SecretRefs[id]
			if ok && ref.Name != "" {
				if ref.Namespace != "" && ref.Namespace != namespace {
					return spec.Err(16, "secret reference escapes target namespace")
				}
				add("", "secrets", ref.Name, "get")
			}
		}
		return nil
	}
	// These reads are the fixed target/checkpoint observer, not a broad grant.
	for _, kind := range []string{"Deployment", "StatefulSet", "ConfigMap", "Service", "PersistentVolumeClaim", "Secret"} {
		r := permissionResources[kind]
		add(r.group, r.resource, "", "list")
	}
	required["namespace"] = authorizationv1.ResourceAttributes{Resource: "namespaces", Name: namespace, Verb: "get"}
	add("", "secrets", "", "get") // Helm's default release storage.
	lease := "cinderlock-" + fingerprint(e.Site.Spec.ReleaseName)[7:27]
	add("coordination.k8s.io", "leases", lease, "get", "create", "update", "delete")
	add("", "configmaps", "", "get", "list", "create", "update")
	jobs, restart, helm, uninstall, probe := len(p.Checks) > 0, false, false, false, false
	observations := false
	for _, check := range p.Checks {
		observations = observations || check.ObservationContract != nil
	}
	for _, op := range p.Operations {
		switch op.Type {
		case "job", "migrate", "backup", "reindex":
			jobs = true
		case "seed":
			if op.PVC == "" {
				return nil, spec.Err(10, "model seed authorization needs a named volume claim")
			}
			jobs = true
			add("", "persistentvolumeclaims", op.PVC, "get", "create")
			if len(op.Command) == 0 {
				add("", "pods", "", "get", "list")
				a := authorizationv1.ResourceAttributes{Namespace: namespace, Resource: "pods", Subresource: "attach", Verb: "create"}
				required[permissionLabel(a)] = a
			}
		case "probe":
			if op.NodeName == "" {
				return nil, spec.Err(10, "GPU probe authorization needs a named node")
			}
			jobs, probe = true, true
			a := authorizationv1.ResourceAttributes{Resource: "nodes", Name: op.NodeName, Verb: "get"}
			required[permissionLabel(a)] = a
		case "restart":
			if op.Service == "" {
				return nil, spec.Err(10, "restart authorization needs a named Deployment")
			}
			restart = true
			add("apps", "deployments", op.Service, "get", "update")
		case "helm":
			helm = true
		case "uninstall":
			uninstall = true
		case "import":
		default:
			return nil, spec.Err(10, "authorization requirements are not qualified for operation %s", op.Type)
		}
		if err := addSecrets(op.SecretRefs); err != nil {
			return nil, err
		}
	}
	for _, check := range p.Checks {
		if err := addSecrets(check.SecretRefs); err != nil {
			return nil, err
		}
	}
	if jobs {
		add("batch", "jobs", "", "get", "create")
	}
	if restart || probe || observations {
		add("", "pods", "", "list")
	}
	if probe {
		add("", "pods", "", "get")
	}
	if probe || observations {
		a := authorizationv1.ResourceAttributes{Namespace: namespace, Resource: "pods", Subresource: "log", Verb: "get"}
		required[permissionLabel(a)] = a
	}
	if uninstall && len(objects) == 0 {
		return nil, spec.Err(10, "retirement authorization requires the existing Helm object inventory")
	}
	if helm || uninstall {
		if len(objects) == 0 || len(objects) > 256 {
			return nil, spec.Err(10, "Helm authorization requires a bounded rendered object inventory")
		}
		add("", "secrets", "", "create", "update")
		if p.SourceVersion != "" && !uninstall {
			add("", "secrets", "", "delete")
		}
		desired := map[string]bool{}
		for _, object := range objects {
			kind, _ := object["kind"].(string)
			version, _ := object["apiVersion"].(string)
			resource, ok := permissionResources[kind]
			if !ok || version != resource.version {
				return nil, spec.Err(10, "authorization profile does not support API kind %s %s", version, kind)
			}
			metadata, _ := object["metadata"].(map[string]any)
			name, _ := metadata["name"].(string)
			ns, _ := metadata["namespace"].(string)
			if name == "" || ns != "" && ns != namespace {
				return nil, spec.Err(16, "Helm authorization object escapes the named target namespace")
			}
			desired[version+"/"+kind+"/"+name] = true
			if uninstall {
				annotations, _ := metadata["annotations"].(map[string]any)
				add(resource.group, resource.resource, name, "get")
				if annotations["helm.sh/resource-policy"] != "keep" {
					add(resource.group, resource.resource, name, "delete")
				}
			} else {
				add(resource.group, resource.resource, name, "get", "create")
				if p.SourceVersion != "" {
					add(resource.group, resource.resource, name, "patch")
				}
				add(resource.group, resource.resource, "", "list", "watch")
			}
		}
		for _, object := range previous {
			kind, _ := object["kind"].(string)
			version, _ := object["apiVersion"].(string)
			resource, ok := permissionResources[kind]
			metadata, _ := object["metadata"].(map[string]any)
			name, _ := metadata["name"].(string)
			ns, _ := metadata["namespace"].(string)
			if !ok || version != resource.version || name == "" || ns != "" && ns != namespace {
				return nil, spec.Err(10, "installed Helm permission inventory has unsupported target scope")
			}
			annotations, _ := metadata["annotations"].(map[string]any)
			if !desired[version+"/"+kind+"/"+name] && annotations["helm.sh/resource-policy"] != "keep" {
				add(resource.group, resource.resource, name, "get", "delete")
			}
		}
		if !uninstall {
			add("", "pods", "", "get", "list", "watch")
			add("apps", "replicasets", "", "get", "list", "watch")
		}
	}
	keys := make([]string, 0, len(required))
	for key := range required {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]authorizationv1.ResourceAttributes, 0, len(keys))
	for _, key := range keys {
		out = append(out, required[key])
	}
	return out, nil
}

// PermissionObjects decodes the bounded Helm inventory for permission planning.
func PermissionObjects(data []byte) ([]map[string]any, error) {
	if len(data) > 16<<20 {
		return nil, spec.Err(10, "Helm permission inventory exceeds limit")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	objects := []map[string]any{}
	for {
		var object map[string]any
		err := decoder.Decode(&object)
		if err == io.EOF {
			return objects, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode Helm permission inventory: %w", err)
		}
		if len(object) == 0 {
			continue
		}
		if len(objects) >= 256 {
			return nil, spec.Err(10, "Helm permission inventory exceeds object limit")
		}
		objects = append(objects, object)
	}
}
