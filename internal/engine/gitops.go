package engine

import (
	"context"
	"slices"

	"github.com/cenab/cinderlock/internal/spec"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

type GitOpsObservation struct {
	spec.Header
	Owner                 string `json:"owner"`
	Namespace             string `json:"namespace"`
	Name                  string `json:"name"`
	UID                   string `json:"uid"`
	ExpectedRevision      string `json:"expectedRevision"`
	ObservedRevision      string `json:"observedRevision"`
	Generation            int64  `json:"generation"`
	ObservedGeneration    int64  `json:"observedGeneration"`
	ControllerReady       bool   `json:"controllerReady"`
	ObservedAt            string `json:"observedAt"`
	ControllerObservedAt  string `json:"controllerObservedAt,omitempty"`
	ApplicationAcceptance string `json:"applicationAcceptance"`
	Limit                 string `json:"limit"`
}

func (e *Engine) ObserveGitOps(ctx context.Context, owner, namespace, name, revision string, policy spec.TrustPolicy) (GitOpsObservation, error) {
	if !slices.Contains(e.Site.Spec.AllowedActions, "gitops-observe") || !slices.Contains(policy.Spec.AllowedActions, "gitops-observe") {
		return GitOpsObservation{}, spec.Err(16, "GitOps observation capability is not admitted by both site and policy")
	}
	if owner == "" || namespace == "" || name == "" || revision == "" {
		return GitOpsObservation{}, spec.Err(2, "explicit GitOps owner, namespace, name, and revision are required")
	}
	client := e.DynamicClient
	if client == nil {
		var err error
		client, err = dynamic.NewForConfig(e.Kube.Config)
		if err != nil {
			return GitOpsObservation{}, err
		}
	}
	var resource schema.GroupVersionResource
	switch owner {
	case "argocd":
		resource = schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}
	case "flux":
		resource = schema.GroupVersionResource{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}
	default:
		return GitOpsObservation{}, spec.Err(10, "only Argo CD Application and Flux v1 Kustomization status adapters are supported")
	}
	object, err := client.Resource(resource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return GitOpsObservation{}, err
	}
	return gitOpsStatus(owner, revision, object), nil
}

func gitOpsStatus(owner, revision string, object *unstructured.Unstructured) GitOpsObservation {
	o := GitOpsObservation{Header: spec.NewHeader("GitOpsObservation"), Owner: owner, Namespace: object.GetNamespace(), Name: object.GetName(), UID: string(object.GetUID()), Generation: object.GetGeneration(), ExpectedRevision: revision, ObservedAt: spec.Now(), ApplicationAcceptance: "not_tested", Limit: "controller-reported status only; no application workflow or data recovery was executed"}
	if owner == "argocd" {
		o.ObservedRevision, _, _ = unstructured.NestedString(object.Object, "status", "sync", "revision")
		sync, _, _ := unstructured.NestedString(object.Object, "status", "sync", "status")
		health, _, _ := unstructured.NestedString(object.Object, "status", "health", "status")
		o.ControllerObservedAt, _, _ = unstructured.NestedString(object.Object, "status", "reconciledAt")
		o.ControllerReady = o.ObservedRevision == revision && sync == "Synced" && health == "Healthy" && o.ControllerObservedAt != ""
		o.Limit += "; Argo freshness is its reported reconciledAt, not proof that an upstream moving reference is current"
		return o
	}
	o.ObservedRevision, _, _ = unstructured.NestedString(object.Object, "status", "lastAppliedRevision")
	o.ObservedGeneration, _, _ = unstructured.NestedInt64(object.Object, "status", "observedGeneration")
	conditions, _, _ := unstructured.NestedSlice(object.Object, "status", "conditions")
	ready := false
	for _, entry := range conditions {
		condition, ok := entry.(map[string]any)
		if ok && condition["type"] == "Ready" && condition["status"] == "True" {
			ready = true
		}
	}
	o.ControllerReady = ready && o.ObservedGeneration == o.Generation && o.ObservedRevision == revision
	return o
}
