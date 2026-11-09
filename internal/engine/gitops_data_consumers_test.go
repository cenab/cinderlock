package engine

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGitOpsDataConsumerRequiresReviewedPodAndOwnership(t *testing.T) {
	ctx := context.Background()
	f := newGitOpsExecutionFixture(t, gitOpsFixtureOptions{data: true})
	deployments, err := f.kube.AppsV1().Deployments("test").List(ctx, metav1.ListOptions{})
	if err != nil || len(deployments.Items) != 1 {
		t.Fatal("reviewed application unavailable", err)
	}
	d := deployments.Items[0]
	yes := true
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "application-rs", Namespace: "test", UID: "application-rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: d.Name, UID: d.UID, Controller: &yes}}}, Spec: appsv1.ReplicaSetSpec{Selector: d.Spec.Selector.DeepCopy(), Template: *d.Spec.Template.DeepCopy()}}
	if _, err := f.kube.AppsV1().ReplicaSets("test").Create(ctx, rs, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"none", "scheduled", "command", "selector", "owner-uid", "mount", "sidecar"} {
		t.Run(change, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "application-pod", Namespace: "test", UID: "application-pod-uid", Labels: d.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}}, Spec: *d.Spec.Template.Spec.DeepCopy()}
			switch change {
			case "scheduled":
				seconds := int64(300)
				pod.Spec.NodeName = "scheduled-node"
				pod.Spec.ServiceAccountName = "default"
				pod.Spec.Tolerations = []corev1.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &seconds}}
			case "command":
				pod.Spec.Containers[0].Command = []string{"/unreviewed/writer"}
			case "selector":
				pod.Labels = map[string]string{"unrelated": "application"}
			case "owner-uid":
				pod.OwnerReferences[0].UID = "replacement-rs-uid"
			case "mount":
				pod.Spec.Containers[0].VolumeMounts[0].MountPath = "/different"
			case "sidecar":
				pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "injected", Image: "unreviewed.invalid/writer"})
			}
			if _, err := f.kube.CoreV1().Pods("test").Create(ctx, pod, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := f.kube.CoreV1().Pods("test").Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
					t.Error(err)
				}
			}()
			p, err := f.e.GitOpsDataChecksPlan(ctx, f.v, "verified.cinder", f.sitePath, f.policy, f.binding)
			if change == "none" || change == "scheduled" {
				if err != nil || !p.Executable {
					t.Fatal("reviewed Pod was rejected", err, p.Findings)
				}
			} else if err == nil {
				t.Fatal("unreviewed claim consumer produced a plan", change)
			}
		})
	}
}
