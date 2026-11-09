package engine

import (
	"context"
	"errors"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// jobRecipe excludes API defaults that do not change the admitted worker, but
// preserves commands, images, credentials, mounts, resources and isolation.
func jobRecipe(job *batchv1.Job) (string, error) {
	if job.Spec.Parallelism != nil && *job.Spec.Parallelism != 1 || job.Spec.Completions != nil && *job.Spec.Completions != 1 || job.Spec.Suspend != nil && *job.Spec.Suspend || job.Spec.PodFailurePolicy != nil || job.Spec.SuccessPolicy != nil {
		return "", errors.New("Job concurrency or completion policy differs from fixed worker")
	}
	pod := job.Spec.Template.Spec.DeepCopy()
	if len(pod.Containers) != 1 || len(pod.InitContainers) != 0 || len(pod.EphemeralContainers) != 0 {
		return "", errors.New("Job container scope differs from fixed worker")
	}
	if pod.ServiceAccountName == "default" {
		pod.ServiceAccountName = ""
	}
	if pod.DeprecatedServiceAccount == "default" {
		pod.DeprecatedServiceAccount = ""
	}
	if pod.DNSPolicy == corev1.DNSClusterFirst {
		pod.DNSPolicy = ""
	}
	if pod.SchedulerName == "default-scheduler" {
		pod.SchedulerName = ""
	}
	if pod.TerminationGracePeriodSeconds != nil && *pod.TerminationGracePeriodSeconds == 30 {
		pod.TerminationGracePeriodSeconds = nil
	}
	if pod.EnableServiceLinks != nil && *pod.EnableServiceLinks {
		pod.EnableServiceLinks = nil
	}
	if pod.PreemptionPolicy != nil && *pod.PreemptionPolicy == corev1.PreemptLowerPriority {
		pod.PreemptionPolicy = nil
	}
	if pod.Priority != nil && *pod.Priority == 0 {
		pod.Priority = nil
	}
	for i := range pod.Containers {
		container := &pod.Containers[i]
		if container.TerminationMessagePath == "/dev/termination-log" {
			container.TerminationMessagePath = ""
		}
		if container.TerminationMessagePolicy == corev1.TerminationMessageReadFile {
			container.TerminationMessagePolicy = ""
		}
	}
	for i := range pod.Volumes {
		if source := pod.Volumes[i].ConfigMap; source != nil && source.DefaultMode != nil && *source.DefaultMode == 0644 {
			source.DefaultMode = nil
		}
	}
	return spec.Digest(struct {
		Pod      *corev1.PodSpec `json:"pod"`
		Backoff  *int32          `json:"backoff"`
		Deadline *int64          `json:"deadline"`
	}{pod, job.Spec.BackoffLimit, job.Spec.ActiveDeadlineSeconds})
}

// workerJob binds only the original Job. Consumer inventories use this seam to
// avoid recursively validating the same claim's mounted provenance.
func (e *Engine) workerJob(ctx context.Context, worker state.Worker) (*batchv1.Job, error) {
	job, err := e.Kube.Client.BatchV1().Jobs(e.Site.Spec.Namespace).Get(ctx, worker.Name, metav1.GetOptions{})
	if err != nil {
		return nil, spec.Err(13, "recorded Job identity cannot be observed: %v", err)
	}
	digest, err := jobRecipe(job)
	if err != nil || string(job.UID) != worker.UID || job.Labels["cinderlock.dev/run"] != worker.RunID || job.Labels["cinderlock.dev/step"] != fingerprint(worker.Role)[7:23] || digest != worker.RecipeDigest || job.Annotations["cinderlock.dev/recipe-digest"] != worker.RecipeDigest {
		return nil, spec.Err(13, "Job UID, ownership or recipe differs from recorded worker; replacement cannot establish completion")
	}
	return job, nil
}

func (e *Engine) inspectWorker(ctx context.Context, worker state.Worker) (string, error) {
	job, err := e.workerJob(ctx, worker)
	if err != nil {
		return "unknown", err
	}
	if err := e.mountedFixtureBindings(ctx, job, worker.RunID); err != nil {
		return "unknown", err
	}
	if err := e.inspectModelJobProvenance(ctx, job); err != nil {
		return "unknown", err
	}
	for _, condition := range job.Status.Conditions {
		if condition.Status == corev1.ConditionTrue {
			if condition.Type == batchv1.JobComplete {
				return "complete", nil
			}
			if condition.Type == batchv1.JobFailed {
				return "failed", nil
			}
		}
	}
	return "running", nil
}

func (e *Engine) operationWorker(ctx context.Context, runID, stepID string, attempt int, role string) (state.Worker, error) {
	worker, err := e.Store.Worker(ctx, runID, stepID, attempt, role)
	if err != nil {
		return worker, spec.Err(13, "Job server UID was not durably recorded; terminal name alone cannot establish an outcome")
	}
	return worker, nil
}

func workerPodRecipe(job *batchv1.Job, pod *corev1.Pod, w state.Worker) (string, error) {
	owner := metav1.GetControllerOf(pod)
	if string(job.UID) != w.UID || pod.UID == "" || pod.DeletionTimestamp != nil || owner == nil || owner.Kind != "Job" || owner.APIVersion != "batch/v1" || owner.UID != job.UID || owner.Name != job.Name || pod.Labels["cinderlock.dev/run"] != w.RunID || pod.Labels["cinderlock.dev/step"] != fingerprint(w.Role)[7:23] {
		return "", spec.Err(13, "Pod is not the original controlled worker")
	}
	actual := job.DeepCopy()
	actual.Spec.Template.Spec = *pod.Spec.DeepCopy()
	if job.Spec.Template.Spec.NodeName == "" {
		actual.Spec.Template.Spec.NodeName = ""
	}
	tolerations := []corev1.Toleration{}
	for _, value := range actual.Spec.Template.Spec.Tolerations {
		if (value.Key == "node.kubernetes.io/not-ready" || value.Key == "node.kubernetes.io/unreachable") && value.Operator == corev1.TolerationOpExists && value.Effect == corev1.TaintEffectNoExecute && value.Value == "" && value.TolerationSeconds != nil && *value.TolerationSeconds == 300 {
			continue
		}
		tolerations = append(tolerations, value)
	}
	if len(tolerations) == 0 {
		actual.Spec.Template.Spec.Tolerations = nil
	} else {
		actual.Spec.Template.Spec.Tolerations = tolerations
	}
	digest, err := jobRecipe(actual)
	if err != nil || digest != w.RecipeDigest {
		return "", spec.Err(13, "Pod differs from its admitted Job recipe")
	}
	return digest, nil
}
