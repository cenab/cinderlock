package engine

import (
	"bytes"
	"context"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (e *Engine) UninstallPlan(ctx context.Context, v *bundle.Verified, bundlePath, sitePath string, policy spec.TrustPolicy) (spec.Plan, error) {
	if err := spec.ValidateRelease(v.Index.Lock.Release); err != nil {
		return spec.Plan{}, err
	}
	if !slices.Contains(e.Site.Spec.AllowedActions, "uninstall") || !slices.Contains(policy.Spec.AllowedActions, "uninstall") {
		return spec.Plan{}, spec.Err(16, "retirement needs customer site and policy uninstall capability")
	}
	snapshot, err := e.Inspect(ctx)
	if err != nil {
		return spec.Plan{}, err
	}
	if snapshot.InstalledVersion == "" {
		return spec.Plan{}, spec.Err(10, "no adopted Helm release is installed")
	}
	retained, err := e.uninstallInventory(ctx)
	if err != nil {
		return spec.Plan{}, err
	}
	p := spec.Plan{Header: spec.NewHeader("RetirementPlan"), BundlePath: bundlePath, BundleDigest: v.Digest, SitePath: sitePath, Snapshot: snapshot, SourceVersion: snapshot.InstalledVersion, TargetVersion: "", TransitionID: "retain-data-uninstall", Operations: []spec.Operation{{ID: "uninstall", Type: "uninstall", TimeoutSeconds: 300}}, Checks: []spec.Check{}, RequiredChecks: []string{}, Recovery: v.Index.Lock.Release.Spec.Recovery, RetainedResources: retained, CreatedAt: spec.Now(), Executable: true, PolicyEpoch: policy.Spec.Epoch, Findings: []spec.Finding{{Code: "DATA_RETENTION_SCOPE", Severity: "info", Message: "retains the listed Kubernetes object UIDs and Helm history; application data contents, external stores, and reinstall are not certified"}}}
	p.Metadata = v.Index.Lock.Release.Metadata
	p.SiteDigest, err = spec.Digest(e.Site)
	if err != nil {
		return p, err
	}
	p.SourceSiteDigest, err = sourceSiteDigest(sitePath)
	if err != nil {
		return p, err
	}
	p.PolicyDigest, err = spec.Digest(policy)
	if err != nil {
		return p, err
	}
	e.addPolicyFloorFindings(ctx, &p)
	e.addExecutionFindings(ctx, &p, v, policy)
	e.addStorageFindings(ctx, &p, v, policy)
	p.SnapshotDigest, err = snapshotDigest(snapshot)
	if err != nil {
		return p, err
	}
	manifest, err := e.helm(ctx, "get", "manifest", e.Site.Spec.ReleaseName)
	if err != nil {
		return p, err
	}
	objects, err := PermissionObjects(manifest)
	if err != nil {
		return p, err
	}
	e.addPermissionFindings(ctx, &p, objects)
	return p, err
}

func (e *Engine) uninstallInventory(ctx context.Context) ([]spec.ResourceFact, error) {
	manifest, err := e.helm(ctx, "get", "manifest", e.Site.Spec.ReleaseName)
	if err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(manifest))
	objects := []map[string]any{}
	removed := map[string]bool{}
	allowed := map[string]bool{"Deployment": true, "StatefulSet": true, "Service": true, "ConfigMap": true, "Secret": true, "PersistentVolumeClaim": true, "ServiceAccount": true, "Role": true, "RoleBinding": true, "NetworkPolicy": true, "PodDisruptionBudget": true}
	for {
		var object map[string]any
		err := decoder.Decode(&object)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(object) == 0 {
			continue
		}
		kind, _ := object["kind"].(string)
		if !allowed[kind] {
			return nil, spec.Err(10, "retirement cannot prove safe scope for kind %s", kind)
		}
		metadata, _ := object["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		ns, _ := metadata["namespace"].(string)
		if name == "" || ns != "" && ns != e.Site.Spec.Namespace {
			return nil, spec.Err(16, "retirement manifest escapes the admitted namespace")
		}
		objects = append(objects, object)
		annotations, _ := metadata["annotations"].(map[string]any)
		if annotations["helm.sh/resource-policy"] != "keep" {
			removed[kind+"/"+name] = true
		} else if kind == "Deployment" || kind == "StatefulSet" {
			return nil, spec.Err(10, "retirement cannot leave an active workload marked keep: %s/%s", kind, name)
		}
	}
	if len(objects) == 0 {
		return nil, spec.Err(10, "existing Helm manifest is empty")
	}
	retained := []spec.ResourceFact{}
	seen := map[string]bool{}
	add := func(kind string, meta metav1.ObjectMeta) error {
		if meta.UID == "" || meta.DeletionTimestamp != nil {
			return spec.Err(10, "retained resource %s/%s has no stable live UID", kind, meta.Name)
		}
		for _, owner := range meta.OwnerReferences {
			if removed[owner.Kind+"/"+owner.Name] {
				return spec.Err(10, "retained resource %s/%s would be garbage-collected with %s/%s", kind, meta.Name, owner.Kind, owner.Name)
			}
		}
		key := kind + "/" + meta.Name
		if !seen[key] {
			retained = append(retained, spec.ResourceFact{Kind: kind, Namespace: e.Site.Spec.Namespace, Name: meta.Name, UID: string(meta.UID), Fingerprint: TargetIdentity(kind, string(meta.UID))})
			seen[key] = true
		}
		return nil
	}
	for _, object := range objects {
		kind, _ := object["kind"].(string)
		metadata, _ := object["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		annotations, _ := metadata["annotations"].(map[string]any)
		if kind == "ConfigMap" || kind == "Secret" || kind == "PersistentVolumeClaim" {
			if annotations["helm.sh/resource-policy"] != "keep" {
				return nil, spec.Err(10, "retirement requires helm.sh/resource-policy: keep on %s/%s; no data-disposable assumption is made", kind, name)
			}
			meta, err := e.retainedMetadata(ctx, kind, name)
			if err != nil {
				return nil, err
			}
			if err := add(kind, meta); err != nil {
				return nil, err
			}
		}
		if kind == "Deployment" || kind == "StatefulSet" {
			body, _ := object["spec"].(map[string]any)
			template, _ := body["template"].(map[string]any)
			pod, _ := template["spec"].(map[string]any)
			containers, _ := pod["containers"].([]any)
			for _, value := range containers {
				container, _ := value.(map[string]any)
				if container["lifecycle"] != nil {
					return nil, spec.Err(10, "opaque Pod lifecycle hooks need a separately qualified retirement procedure")
				}
			}
		}
		if kind == "StatefulSet" {
			set, err := e.Kube.Client.AppsV1().StatefulSets(e.Site.Spec.Namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			if set.Spec.PersistentVolumeClaimRetentionPolicy != nil && string(set.Spec.PersistentVolumeClaimRetentionPolicy.WhenDeleted) != "Retain" {
				return nil, spec.Err(10, "StatefulSet deletion would remove its volume claims")
			}
			claims, err := e.Kube.Client.CoreV1().PersistentVolumeClaims(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			for _, template := range set.Spec.VolumeClaimTemplates {
				prefix := template.Name + "-" + set.Name + "-"
				for _, claim := range claims.Items {
					if strings.HasPrefix(claim.Name, prefix) {
						if err := add("PersistentVolumeClaim", claim.ObjectMeta); err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}
	sort.Slice(retained, func(i, j int) bool {
		return retained[i].Kind+"/"+retained[i].Name < retained[j].Kind+"/"+retained[j].Name
	})
	return retained, nil
}

func (e *Engine) retainedMetadata(ctx context.Context, kind, name string) (metav1.ObjectMeta, error) {
	switch kind {
	case "PersistentVolumeClaim":
		o, err := e.Kube.Client.CoreV1().PersistentVolumeClaims(e.Site.Spec.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return metav1.ObjectMeta{}, err
		}
		return o.ObjectMeta, nil
	case "Secret":
		o, err := e.Kube.Client.CoreV1().Secrets(e.Site.Spec.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return metav1.ObjectMeta{}, err
		}
		return o.ObjectMeta, nil
	case "ConfigMap":
		o, err := e.Kube.Client.CoreV1().ConfigMaps(e.Site.Spec.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return metav1.ObjectMeta{}, err
		}
		return o.ObjectMeta, nil
	}
	return metav1.ObjectMeta{}, spec.Err(10, "unsupported retained resource kind")
}

func (e *Engine) verifyRetained(ctx context.Context, resources []spec.ResourceFact) error {
	for _, resource := range resources {
		if resource.Namespace != e.Site.Spec.Namespace {
			return spec.Err(16, "retained resource namespace differs from site")
		}
		meta, err := e.retainedMetadata(ctx, resource.Kind, resource.Name)
		if err != nil {
			return spec.Err(13, "retained resource is unavailable: %s/%s", resource.Kind, resource.Name)
		}
		if string(meta.UID) != resource.UID || meta.DeletionTimestamp != nil {
			return spec.Err(13, "retained resource UID changed or deletion started: %s/%s", resource.Kind, resource.Name)
		}
	}
	return nil
}

func (e *Engine) uninstall(ctx context.Context, p spec.Plan) error {
	current, err := e.uninstallInventory(ctx)
	if err != nil {
		return err
	}
	retained := append([]spec.ResourceFact{}, p.RetainedResources...)
	expected, _ := spec.Digest(struct {
		Resources []spec.ResourceFact `json:"resources"`
	}{retained})
	actual, _ := spec.Digest(struct {
		Resources []spec.ResourceFact `json:"resources"`
	}{current})
	if actual != expected {
		return spec.Err(11, "retention inventory changed after retirement approval")
	}
	if _, err := e.helm(ctx, "uninstall", e.Site.Spec.ReleaseName, "--keep-history", "--no-hooks", "--cascade", "foreground", "--wait", "--timeout", "5m"); err != nil {
		return spec.Err(13, "Helm retirement outcome needs reconciliation: %v", err)
	}
	return e.verifyRetained(ctx, p.RetainedResources)
}
