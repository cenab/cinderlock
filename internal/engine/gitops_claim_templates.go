package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/spec"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type gitOpsClaimTemplate struct {
	Kind string
	Meta metav1.ObjectMeta
	Pod  corev1.PodSpec
}

// This closed census includes pending native controllers, before they create Pods.
func (e *Engine) gitOpsClaimTemplates(ctx context.Context) ([]gitOpsClaimTemplate, error) {
	options := metav1.ListOptions{Limit: 257}
	var templates []gitOpsClaimTemplate
	failure := func() ([]gitOpsClaimTemplate, error) {
		return nil, spec.Err(10, "declared claim controller-template inventory is unavailable or exceeds its bound")
	}
	namespace := e.Site.Spec.Namespace
	deployments, err := e.Kube.Client.AppsV1().Deployments(namespace).List(ctx, options)
	if err != nil || deployments.Continue != "" || len(deployments.Items) > 256 {
		return failure()
	}
	for _, item := range deployments.Items {
		templates = append(templates, gitOpsClaimTemplate{"Deployment", item.ObjectMeta, item.Spec.Template.Spec})
	}
	sets, err := e.Kube.Client.AppsV1().StatefulSets(namespace).List(ctx, options)
	if err != nil || sets.Continue != "" || len(sets.Items) > 256 {
		return failure()
	}
	for _, item := range sets.Items {
		templates = append(templates, gitOpsClaimTemplate{"StatefulSet", item.ObjectMeta, item.Spec.Template.Spec})
	}
	daemons, err := e.Kube.Client.AppsV1().DaemonSets(namespace).List(ctx, options)
	if err != nil || daemons.Continue != "" || len(daemons.Items) > 256 {
		return failure()
	}
	for _, item := range daemons.Items {
		templates = append(templates, gitOpsClaimTemplate{"DaemonSet", item.ObjectMeta, item.Spec.Template.Spec})
	}
	replicas, err := e.Kube.Client.AppsV1().ReplicaSets(namespace).List(ctx, options)
	if err != nil || replicas.Continue != "" || len(replicas.Items) > 256 {
		return failure()
	}
	for _, item := range replicas.Items {
		templates = append(templates, gitOpsClaimTemplate{"ReplicaSet", item.ObjectMeta, item.Spec.Template.Spec})
	}
	cron, err := e.Kube.Client.BatchV1().CronJobs(namespace).List(ctx, options)
	if err != nil || cron.Continue != "" || len(cron.Items) > 256 {
		return failure()
	}
	for _, item := range cron.Items {
		templates = append(templates, gitOpsClaimTemplate{"CronJob", item.ObjectMeta, item.Spec.JobTemplate.Spec.Template.Spec})
	}
	jobs, err := e.Kube.Client.BatchV1().Jobs(namespace).List(ctx, options)
	if err != nil || jobs.Continue != "" || len(jobs.Items) > 256 {
		return failure()
	}
	for _, item := range jobs.Items {
		templates = append(templates, gitOpsClaimTemplate{"Job", item.ObjectMeta, item.Spec.Template.Spec})
	}
	controllers, err := e.Kube.Client.CoreV1().ReplicationControllers(namespace).List(ctx, options)
	if err != nil || controllers.Continue != "" || len(controllers.Items) > 256 {
		return failure()
	}
	for _, item := range controllers.Items {
		if item.Spec.Template == nil {
			return failure()
		}
		templates = append(templates, gitOpsClaimTemplate{"ReplicationController", item.ObjectMeta, item.Spec.Template.Spec})
	}
	podTemplates, err := e.Kube.Client.CoreV1().PodTemplates(namespace).List(ctx, options)
	if err != nil || podTemplates.Continue != "" || len(podTemplates.Items) > 256 {
		return failure()
	}
	for _, item := range podTemplates.Items {
		templates = append(templates, gitOpsClaimTemplate{"PodTemplate", item.ObjectMeta, item.Template.Spec})
	}
	return templates, nil
}
