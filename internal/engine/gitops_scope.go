package engine

import (
	"context"
	"sort"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func (e *Engine) inspectGitOpsPlan(ctx context.Context, p spec.Plan, v *bundle.Verified, policy spec.TrustPolicy) (spec.TargetSnapshot, error) {
	if gitOpsDataPhase(p) {
		return e.inspectGitOpsData(ctx, p, v, policy)
	}
	if p.Kind == "GitOpsPreparePlan" {
		return e.inspectGitOpsPreparation(ctx, p, v, policy)
	}
	var snapshot spec.TargetSnapshot
	if p.GitOps == nil || p.GitOps.Contract == nil {
		return snapshot, spec.Err(12, "GitOps checks have no admitted source contract")
	}
	manifest, err := ReadGitOpsManifest(p.GitOps.ManifestPath)
	if err != nil || spec.Hash(manifest) != p.DesiredStateDigest {
		return snapshot, spec.Err(11, "reviewed GitOps input bytes changed")
	}
	observation, err := e.ObserveGitOpsProfile(ctx, v, policy, p.SitePath, *p.GitOps.Contract, manifest)
	if err != nil || !observation.Ready {
		return snapshot, spec.Err(10, "fresh GitOps controller/source/resource readiness is not established")
	}
	if _, err = e.gitOpsStageReference(ctx, p.GitOps.Staging, v, p.SitePath, policy, false); err != nil {
		return snapshot, err
	}
	snapshot, err = e.inspectArtifacts(ctx)
	if err != nil {
		return snapshot, err
	}
	fingerprint, resources, err := gitOpsObservationBindings(p, v.Digest, observation)
	if err != nil {
		return snapshot, err
	}
	snapshot.Facts = append(snapshot.Facts, spec.Fact{Name: "gitops/source", Value: fingerprint, Status: "known", Source: "exact accepted source and current controller contract"})
	snapshot.Resources = append(snapshot.Resources, resources...)
	for _, resource := range observation.Resources {
		snapshot.Facts = append(snapshot.Facts, spec.Fact{Name: "readiness/" + resource.Kind + "/" + resource.Name, Value: "true", Status: "known", Source: "fresh bounded Argo directory profile and actual resource readiness"})
	}
	secrets, err := e.gitOpsSelectedSecretFacts(ctx, p, v)
	if err != nil {
		return snapshot, err
	}
	snapshot.Facts = append(snapshot.Facts, secrets...)
	objects, err := PermissionObjects(manifest)
	if err != nil {
		return snapshot, err
	}
	dependencies, err := e.gitOpsWorkloadDependencies(ctx, p, v, objects)
	if err != nil {
		return snapshot, err
	}
	snapshot.Facts = append(snapshot.Facts, dependencies...)
	currentManifest, err := ReadGitOpsManifest(p.GitOps.ManifestPath)
	if err != nil || spec.Hash(currentManifest) != p.DesiredStateDigest {
		return snapshot, spec.Err(11, "reviewed GitOps input changed during dependency observation")
	}
	final, err := e.ObserveGitOpsProfile(ctx, v, policy, p.SitePath, *p.GitOps.Contract, currentManifest)
	if err != nil || !final.Ready {
		return snapshot, spec.Err(10, "GitOps source/controller readiness or original freshness changed during dependency observation")
	}
	finalFingerprint, finalResources, err := gitOpsObservationBindings(p, v.Digest, final)
	initialResources, digestErr := spec.Digest(resources)
	currentResources, currentErr := spec.Digest(finalResources)
	if err != nil || digestErr != nil || currentErr != nil || fingerprint != finalFingerprint || initialResources != currentResources || observation.TargetID != final.TargetID || observation.NamespaceUID != final.NamespaceUID {
		return snapshot, spec.Err(11, "GitOps source or resource identity changed during dependency observation")
	}
	return gitOpsSortedSnapshot(snapshot), nil
}

func gitOpsObservationBindings(p spec.Plan, bundleDigest string, observation GitOpsProfileObservation) (string, []spec.ResourceFact, error) {
	scope := struct {
		Contract                                         spec.GitOpsProfileContract
		SourceBlob, SourcePath, Manifest, Bundle, AppUID string
	}{*p.GitOps.Contract, observation.SourceBlob, observation.SourcePath, p.DesiredStateDigest, bundleDigest, observation.UID}
	fingerprint, err := spec.Digest(scope)
	if err != nil {
		return "", nil, err
	}
	resources := []spec.ResourceFact{{Kind: "Application", Namespace: observation.Namespace, Name: observation.Name, UID: observation.UID, Fingerprint: fingerprint}}
	for _, resource := range observation.Resources {
		fingerprint, err := spec.Digest(struct{ APIVersion, Kind, Namespace, Name, UID, Manifest, Owner, Installation string }{resource.APIVersion, resource.Kind, resource.Namespace, resource.Name, resource.UID, p.DesiredStateDigest, observation.Name, p.GitOps.Contract.InstallationID})
		if err != nil {
			return "", nil, err
		}
		resources = append(resources, spec.ResourceFact{Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name, UID: resource.UID, Fingerprint: fingerprint})
	}
	return fingerprint, resources, nil
}

func gitOpsSortedSnapshot(snapshot spec.TargetSnapshot) spec.TargetSnapshot {
	sort.Slice(snapshot.Resources, func(i, j int) bool {
		a, b := snapshot.Resources[i], snapshot.Resources[j]
		return a.Kind+"/"+a.Namespace+"/"+a.Name < b.Kind+"/"+b.Namespace+"/"+b.Name
	})
	sort.Slice(snapshot.Facts, func(i, j int) bool { return snapshot.Facts[i].Name < snapshot.Facts[j].Name })
	return snapshot
}

func (e *Engine) gitOpsSecretFact(ctx context.Context, name, secretName, key string) (spec.Fact, error) {
	fact := spec.Fact{Name: name, Status: "known", Source: "selected Kubernetes Secret UID/type/data private binding"}
	secret, err := e.Kube.Client.CoreV1().Secrets(e.Site.Spec.Namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil || secret.UID == "" || secret.DeletionTimestamp != nil || secret.Name != secretName || secret.Namespace != e.Site.Spec.Namespace {
		return fact, spec.Err(10, "a declared critical Secret identity is unavailable")
	}
	data := secret.Data
	if key != "" {
		value, exists := data[key]
		if !exists {
			return fact, spec.Err(10, "a declared critical Secret key is unavailable")
		}
		data = map[string][]byte{key: value}
	}
	fact.Value, err = e.secretFingerprint(secret, data)
	if err != nil {
		return fact, spec.Err(10, "a declared critical Secret cannot be privately bound")
	}
	return fact, nil
}

func (e *Engine) gitOpsSelectedSecretFacts(ctx context.Context, p spec.Plan, v *bundle.Verified) ([]spec.Fact, error) {
	selected := map[string]bool{}
	for _, op := range p.Operations {
		for _, id := range op.SecretRefs {
			selected[id] = true
		}
	}
	for _, check := range p.Checks {
		for _, id := range check.SecretRefs {
			selected[id] = true
		}
	}
	if (gitOpsApplicationChecks(p) || p.Kind == "GitOpsDataPlan") && v.Index.Lock.Release.Spec.License != nil {
		selected[v.Index.Lock.Release.Spec.License.SecretRef] = true
	}
	if len(selected) > 64 || len(e.Site.Spec.ImagePullSecrets) > 64 {
		return nil, spec.Err(10, "GitOps selected credential scope exceeds its bound")
	}
	facts := []spec.Fact{}
	for id := range selected {
		if id == e.Site.Spec.RegistryAuthRef {
			continue
		}
		ref, exists := e.Site.Spec.SecretRefs[id]
		if !exists || ref.File != "" || ref.Name == "" || ref.Key == "" || ref.Namespace != "" && ref.Namespace != e.Site.Spec.Namespace {
			return nil, spec.Err(16, "GitOps worker credentials need explicit Site name/key references in the target namespace")
		}
		fact, err := e.gitOpsSecretFact(ctx, "secret/"+id, ref.Name, ref.Key)
		if err != nil {
			return nil, err
		}
		facts = append(facts, fact)
	}
	for _, name := range e.Site.Spec.ImagePullSecrets {
		fact, err := e.gitOpsSecretFact(ctx, "secret/image-pull-"+name, name, "")
		if err != nil {
			return nil, err
		}
		facts = append(facts, fact)
	}
	return facts, nil
}

func (e *Engine) gitOpsWorkloadDependencies(ctx context.Context, p spec.Plan, v *bundle.Verified, objects []map[string]any) ([]spec.Fact, error) {
	configMaps := map[string]bool{}
	for _, object := range objects {
		if object["kind"] == "ConfigMap" {
			metadata, _ := object["metadata"].(map[string]any)
			name, _ := metadata["name"].(string)
			configMaps[name] = true
		}
	}
	facts := []spec.Fact{}
	seenSecrets := map[string]bool{}
	secret := func(name, key string) error {
		id := name + "/" + key
		if seenSecrets[id] {
			return nil
		}
		seenSecrets[id] = true
		permitted := false
		for _, ref := range e.Site.Spec.SecretRefs {
			permitted = permitted || ref.File == "" && ref.Name == name && (ref.Namespace == "" || ref.Namespace == e.Site.Spec.Namespace) && (ref.Key == "" || key != "" && ref.Key == key)
		}
		if !permitted {
			return spec.Err(16, "a reviewed workload Secret use is outside independently selected Site scope")
		}
		fact, err := e.gitOpsSecretFact(ctx, "gitops/secret/"+id, name, key)
		if err == nil {
			facts = append(facts, fact)
		}
		return err
	}
	config := func(name string) error {
		if !configMaps[name] {
			return spec.Err(10, "external ConfigMap dependency is outside this reviewed GitOps inventory")
		}
		return nil
	}
	for _, object := range objects {
		if object["kind"] != "Deployment" {
			continue
		}
		var deployment appsv1.Deployment
		if runtime.DefaultUnstructuredConverter.FromUnstructured(object, &deployment) != nil {
			return nil, spec.Err(10, "reviewed workload dependency scope is malformed")
		}
		pod := deployment.Spec.Template.Spec
		if len(pod.EphemeralContainers) != 0 {
			return nil, spec.Err(10, "ephemeral application containers require another supported dependency profile")
		}
		containers := append(append([]corev1.Container{}, pod.InitContainers...), pod.Containers...)
		for _, ref := range pod.ImagePullSecrets {
			admitted := false
			for _, name := range e.Site.Spec.ImagePullSecrets {
				admitted = admitted || name == ref.Name
			}
			if !admitted {
				return nil, spec.Err(16, "reviewed workload image-pull credentials are not selected by Site")
			}
			fact, err := e.gitOpsSecretFact(ctx, "gitops/image-pull/"+ref.Name, ref.Name, "")
			if err != nil {
				return nil, err
			}
			facts = append(facts, fact)
		}
		for _, container := range containers {
			if len(container.VolumeDevices) > 0 {
				return nil, spec.Err(10, "raw application block devices require another supported data profile")
			}
			for _, env := range container.Env {
				if env.ValueFrom != nil {
					if ref := env.ValueFrom.SecretKeyRef; ref != nil {
						if err := secret(ref.Name, ref.Key); err != nil {
							return nil, err
						}
					}
					if ref := env.ValueFrom.ConfigMapKeyRef; ref != nil {
						if err := config(ref.Name); err != nil {
							return nil, err
						}
					}
				}
			}
			for _, env := range container.EnvFrom {
				if ref := env.SecretRef; ref != nil {
					if err := secret(ref.Name, ""); err != nil {
						return nil, err
					}
				}
				if ref := env.ConfigMapRef; ref != nil {
					if err := config(ref.Name); err != nil {
						return nil, err
					}
				}
			}
		}
		for _, volume := range pod.Volumes {
			switch {
			case volume.PersistentVolumeClaim != nil:
				if p.GitOps != nil && p.GitOps.Data != nil && volume.PersistentVolumeClaim.ClaimName == p.GitOps.Data.PVC {
					continue
				}
				binding, err := e.gitOpsPreparedVolume(ctx, p, v, volume.PersistentVolumeClaim.ClaimName)
				if err != nil {
					return nil, err
				}
				mounted := false
				for _, container := range containers {
					for _, mount := range container.VolumeMounts {
						if mount.Name == volume.Name {
							mounted = true
							if !mount.ReadOnly || mount.SubPath != binding.SubPath || mount.SubPathExpr != "" {
								return nil, spec.Err(10, "prepared GitOps application mount differs from its native revision binding")
							}
						}
					}
				}
				if !mounted {
					return nil, spec.Err(10, "prepared GitOps volume has no explicit application mount")
				}
				fingerprint, err := spec.Digest(binding)
				if err != nil {
					return nil, err
				}
				facts = append(facts, spec.Fact{Name: "gitops/prepared-volume/" + volume.PersistentVolumeClaim.ClaimName, Value: fingerprint, Status: "known", Source: "original completed native preparation, exact PVC/manifest/verifier and read-only application mapping"})
				if gitOpsDataPhase(p) {
					body, err := spec.Canonical(binding)
					if err != nil {
						return nil, err
					}
					facts = append(facts, spec.Fact{Name: "gitops/prepared-evidence/" + binding.PVC, Value: string(body), Status: "known", Source: "original native model identities retained for later read-only historical observation"})
				}
			case volume.ConfigMap != nil:
				if err := config(volume.ConfigMap.Name); err != nil {
					return nil, err
				}
			case volume.Secret != nil:
				if err := secret(volume.Secret.SecretName, ""); err != nil {
					return nil, err
				}
			case volume.Projected != nil:
				for _, source := range volume.Projected.Sources {
					if source.Secret != nil {
						if err := secret(source.Secret.Name, ""); err != nil {
							return nil, err
						}
					}
					if source.ConfigMap != nil {
						if err := config(source.ConfigMap.Name); err != nil {
							return nil, err
						}
					}
					if source.ClusterTrustBundle != nil || source.PodCertificate != nil {
						return nil, spec.Err(10, "reviewed projected credential dependency requires another supported profile")
					}
				}
			case volume.EmptyDir != nil, volume.DownwardAPI != nil:
			default:
				return nil, spec.Err(10, "reviewed application volume dependency is outside the supported GitOps preparation profile")
			}
		}
	}
	if len(seenSecrets) > 64 {
		return nil, spec.Err(10, "reviewed workload credential scope exceeds its bound")
	}
	return facts, nil
}
