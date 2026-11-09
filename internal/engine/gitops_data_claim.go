package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

func gitOpsSnapshotFact(p spec.Plan, name string) string {
	value := ""
	for _, fact := range p.Snapshot.Facts {
		if fact.Name != name || fact.Status != "known" {
			continue
		}
		if value != "" {
			return ""
		}
		value = fact.Value
	}
	return value
}

func (e *Engine) gitOpsDataClaimFacts(ctx context.Context, p spec.Plan, manifest []byte, resources []spec.ResourceFact) ([]spec.Fact, error) {
	d := p.GitOps.Data
	claim, err := e.Kube.Client.CoreV1().PersistentVolumeClaims(e.Site.Spec.Namespace).Get(ctx, d.PVC, metav1.GetOptions{})
	if err != nil || string(claim.UID) != d.UID || claim.DeletionTimestamp != nil || len(claim.OwnerReferences) != 0 || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName == "" || len(claim.Spec.AccessModes) != 1 || claim.Spec.AccessModes[0] != corev1.ReadWriteOnce || claim.Spec.VolumeMode != nil && *claim.Spec.VolumeMode != corev1.PersistentVolumeFilesystem || claim.Spec.DataSource != nil || claim.Spec.DataSourceRef != nil {
		return nil, spec.Err(11, "mutable data claim is not the selected active bound external RWO filesystem identity")
	}
	fingerprint, err := spec.Digest(struct {
		UID, Volume string
		Class       *string
		Mode        *corev1.PersistentVolumeMode
		Access      []corev1.PersistentVolumeAccessMode
	}{d.UID, claim.Spec.VolumeName, claim.Spec.StorageClassName, claim.Spec.VolumeMode, claim.Spec.AccessModes})
	if err != nil {
		return nil, err
	}
	name := "gitops/data/" + d.PVC
	if d.Predecessor != nil {
		record, err := e.Store.Run(ctx, d.Predecessor.RunID)
		var original spec.Plan
		if err != nil || spec.Decode(record.Plan, &original) != nil || gitOpsSnapshotFact(original, name) != fingerprint {
			return nil, spec.Err(11, "mutable claim backing identity changed across the data handoff")
		}
	}
	inventory, err := e.gitOpsProfileInventory(manifest, *p.GitOps.Contract)
	if err != nil {
		return nil, err
	}
	reviewed := map[string]appsv1.Deployment{}
	writable := false
	for _, object := range inventory {
		if object.GetKind() != "Deployment" {
			continue
		}
		var deployment appsv1.Deployment
		if runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &deployment) != nil {
			return nil, spec.Err(10, "reviewed data workload is malformed")
		}
		mounts, err := gitOpsClaimMounts(deployment.Spec.Template.Spec, d.PVC, "", false)
		if err != nil {
			return nil, err
		}
		if len(mounts) == 0 {
			continue
		}
		reviewed[deployment.Name] = deployment
		for _, mount := range mounts {
			writable = writable || !mount.Mount.ReadOnly && !mount.Volume.PersistentVolumeClaim.ReadOnly
		}
	}
	if len(reviewed) == 0 || !writable {
		return nil, spec.Err(10, "mutable data has no explicit reviewed writable application mapping")
	}
	if err := e.gitOpsDataConsumers(ctx, p, reviewed, resources); err != nil {
		return nil, err
	}
	return []spec.Fact{{Name: name, Value: fingerprint, Status: "known", Source: "selected mutable PVC UID and backing identity; not a content hash or storage fence"}}, nil
}

type gitOpsDataJob struct {
	worker  state.Worker
	job     *batchv1.Job
	current bool
}

func (e *Engine) gitOpsDataConsumerJob(ctx context.Context, p spec.Plan, current, target string, meta metav1.ObjectMeta) (gitOpsDataJob, error) {
	var proof gitOpsDataJob
	runID := meta.Labels["cinderlock.dev/run"]
	record, err := e.Store.Run(ctx, runID)
	var original spec.Plan
	if err != nil || record.Application != p.Metadata.Application || record.Namespace != e.Site.Spec.Namespace || record.TargetID != target || spec.Decode(record.Plan, &original) != nil || !gitOpsDataPhase(original) || original.GitOps == nil || original.GitOps.Data == nil || original.GitOps.Data.PVC != p.GitOps.Data.PVC || original.GitOps.Data.UID != p.GitOps.Data.UID {
		return proof, spec.Err(10, "mutable data claim has an unrecorded or unrelated Job consumer")
	}
	digest, dErr := spec.Digest(original)
	if dErr != nil || digest != record.PlanDigest || original.BundleDigest != record.BundleDigest || original.Snapshot.TargetID != target {
		return proof, spec.Err(13, "historical data Job has a conflicting local Plan identity")
	}
	if record.Active && record.ID != current && record.ID != p.SourceRun {
		return proof, spec.Err(13, "another active data run still owns a writer")
	}
	if err := e.Store.WorkerProtocol(ctx, runID); err != nil {
		return proof, spec.Err(13, "legacy data worker identity is unqualified")
	}
	workers, err := e.Store.Workers(ctx, runID)
	if err != nil {
		return proof, err
	}
	found := false
	for _, worker := range workers {
		if worker.Name == meta.Name && worker.UID == string(meta.UID) {
			proof.worker = worker
			found = true
		}
	}
	if !found {
		return proof, spec.Err(13, "data writer has no original durable worker UID")
	}
	proof.job, err = e.workerJob(ctx, proof.worker)
	if err != nil {
		return proof, err
	}
	proof.current = runID == current
	status := workerStatus(proof.job)
	if !proof.current && status != "complete" && status != "failed" {
		return proof, spec.Err(13, "historical data Job is not confirmed terminal")
	}
	return proof, nil
}

func (e *Engine) gitOpsDataConsumers(ctx context.Context, p spec.Plan, reviewed map[string]appsv1.Deployment, resources []spec.ResourceFact) error {
	target, _, ok := e.gitOpsProfileTarget(ctx, e.Site)
	if !ok {
		return spec.Err(11, "data target identity is unavailable")
	}
	current, err := e.gitOpsActivePlanRun(ctx, p, target)
	if err != nil {
		return err
	}
	templates, err := e.gitOpsClaimTemplates(ctx)
	if err != nil {
		return err
	}
	jobs := map[string]gitOpsDataJob{}
	knownJob := func(meta metav1.ObjectMeta) (gitOpsDataJob, error) {
		if proof, ok := jobs[meta.Name]; ok {
			if string(meta.UID) != proof.worker.UID {
				return proof, spec.Err(13, "data Job identity changed during consumer observation")
			}
			return proof, nil
		}
		proof, err := e.gitOpsDataConsumerJob(ctx, p, current.ID, target, meta)
		if err != nil {
			return proof, err
		}
		jobs[meta.Name] = proof
		return proof, nil
	}
	for _, item := range templates {
		if !gitOpsUsesClaim(item.Pod, p.GitOps.Data.PVC) {
			continue
		}
		if item.Kind == "Job" {
			if _, err := knownJob(item.Meta); err != nil {
				return err
			}
			continue
		}
		if err := e.gitOpsDataApplication(ctx, item.Kind, item.Meta, item.Pod, p.GitOps.Data.PVC, reviewed, resources); err != nil {
			return err
		}
	}
	pods, err := e.Kube.Client.CoreV1().Pods(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{Limit: 257})
	if err != nil || pods.Continue != "" || len(pods.Items) > 256 {
		return spec.Err(10, "mutable data Pod inventory is unavailable or exceeds its bound")
	}
	for _, pod := range pods.Items {
		if !gitOpsUsesClaim(pod.Spec, p.GitOps.Data.PVC) {
			continue
		}
		owner := metav1.GetControllerOf(&pod)
		if owner != nil && owner.Kind == "Job" && owner.APIVersion == "batch/v1" {
			meta := metav1.ObjectMeta{Name: owner.Name, Namespace: pod.Namespace, UID: owner.UID, Labels: pod.Labels}
			proof, err := knownJob(meta)
			if err != nil {
				return err
			}
			if _, err := workerPodRecipe(proof.job, &pod, proof.worker); err != nil {
				return err
			}
			if !proof.current {
				if pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].State.Terminated == nil {
					return spec.Err(13, "historical data writer Pod has not terminated")
				}
			}
			continue
		}
		if err := e.gitOpsDataApplication(ctx, "Pod", pod.ObjectMeta, pod.Spec, p.GitOps.Data.PVC, reviewed, resources); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) gitOpsDataApplication(ctx context.Context, kind string, meta metav1.ObjectMeta, pod corev1.PodSpec, claim string, reviewed map[string]appsv1.Deployment, resources []spec.ResourceFact) error {
	originalKind := kind
	podLabels := meta.Labels
	if meta.UID == "" || meta.Namespace != e.Site.Spec.Namespace || meta.DeletionTimestamp != nil {
		return spec.Err(10, "claim consumer lacks an active unambiguous identity")
	}
	name, uid := meta.Name, meta.UID
	if kind == "Pod" {
		owner := metav1.GetControllerOf(&meta)
		if owner == nil || len(meta.OwnerReferences) != 1 || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" {
			return spec.Err(10, "claim Pod is outside the reviewed Deployment ownership chain")
		}
		rs, err := e.Kube.Client.AppsV1().ReplicaSets(e.Site.Spec.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil || rs.UID != owner.UID || rs.DeletionTimestamp != nil {
			return spec.Err(11, "claim ReplicaSet identity changed")
		}
		selector, err := metav1.LabelSelectorAsSelector(rs.Spec.Selector)
		if err != nil || rs.Spec.Selector == nil || !selector.Matches(labels.Set(podLabels)) {
			return spec.Err(10, "claim Pod does not match its ReplicaSet selector")
		}
		meta, kind = rs.ObjectMeta, "ReplicaSet"
	}
	if kind == "ReplicaSet" {
		owner := metav1.GetControllerOf(&meta)
		if owner == nil || len(meta.OwnerReferences) != 1 || owner.Kind != "Deployment" || owner.APIVersion != "apps/v1" {
			return spec.Err(10, "claim ReplicaSet has no exact reviewed Deployment owner")
		}
		name, uid = owner.Name, owner.UID
	} else if kind != "Deployment" || len(meta.OwnerReferences) != 0 {
		return spec.Err(10, "claim has an unsupported native controller consumer")
	}
	wanted, ok := reviewed[name]
	if !ok {
		return spec.Err(10, "claim controller is outside the reviewed application mapping")
	}
	deployment, err := e.Kube.Client.AppsV1().Deployments(e.Site.Spec.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || deployment.UID != uid || deployment.DeletionTimestamp != nil || len(deployment.OwnerReferences) != 0 {
		return spec.Err(11, "claim Deployment identity changed")
	}
	pinned := false
	for _, resource := range resources {
		if resource.Kind == "Deployment" && resource.Name == name && resource.Namespace == e.Site.Spec.Namespace && resource.UID == string(uid) {
			pinned = true
		}
	}
	if !pinned {
		return spec.Err(11, "claim Deployment differs from the observed source identity")
	}
	if originalKind == "Pod" {
		template := deployment.Spec.Template.Spec
		desired := podRecipeSpec(*controlledPodSpec(template, template))
		actual := podRecipeSpec(*controlledPodSpec(template, pod))
		if !sameGitOpsValue(desired, actual) {
			return spec.Err(10, "claim Pod fields differ from the reviewed application template")
		}
		selector, sErr := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
		if sErr != nil || deployment.Spec.Selector == nil || !selector.Matches(labels.Set(podLabels)) {
			return spec.Err(10, "claim Pod does not match its reviewed Deployment selector")
		}
	}
	expected, err := gitOpsClaimMounts(wanted.Spec.Template.Spec, claim, "", false)
	if err != nil {
		return err
	}
	actual, err := gitOpsClaimMounts(pod, claim, "", false)
	if err != nil || !sameGitOpsValue(expected, actual) {
		return spec.Err(10, "claim consumer differs from the reviewed application mount mapping")
	}
	return nil
}
