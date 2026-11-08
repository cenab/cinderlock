package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/spec"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Kubernetes struct {
	Client         kubernetes.Interface
	Config         *rest.Config
	Namespace      string
	Release        string
	Kubeconfig     string
	Context        string
	configSnapshot []byte
}

type Resource struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	UID         string `json:"uid"`
	Fingerprint string `json:"fingerprint"`
	Ready       bool   `json:"ready"`
}

type Observation struct {
	TargetID          string            `json:"targetID"`
	NamespaceUID      string            `json:"namespaceUID"`
	Server            string            `json:"server"`
	KubernetesVersion string            `json:"kubernetesVersion"`
	Resources         []Resource        `json:"resources"`
	GPUs              map[string]string `json:"gpuAllocatableByNode"`
	GPUEvidence       string            `json:"gpuEvidence"`
	Findings          []string          `json:"findings"`
}

func NewKubernetes(kubeconfig, contextName, namespace, release string) (*Kubernetes, error) {
	if kubeconfig == "" || contextName == "" || namespace == "" || release == "" {
		return nil, errors.New("explicit kubeconfig, context, namespace, and release are required")
	}
	data, err := readKubernetesInput(kubeconfig, maxKubeconfigBytes)
	if err != nil {
		return nil, err
	}
	raw, err := clientcmd.Load(data)
	if err != nil {
		return nil, errors.New("cannot parse Kubernetes configuration")
	}
	selected, ok := raw.Contexts[contextName]
	if !ok || selected == nil {
		return nil, errors.New("selected kubeconfig context does not exist")
	}
	cluster, ok := raw.Clusters[selected.Cluster]
	if !ok || cluster == nil {
		return nil, errors.New("selected cluster missing from kubeconfig")
	}
	if cluster.InsecureSkipTLSVerify {
		return nil, errors.New("kubeconfig insecure-skip-tls-verify is not supported")
	}
	u, err := url.Parse(cluster.Server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("Kubernetes API must use an explicit HTTPS URL without embedded credentials")
	}
	if cluster.ProxyURL != "" {
		return nil, errors.New("kubeconfig proxy routes need a separately qualified profile")
	}
	auth, ok := raw.AuthInfos[selected.AuthInfo]
	if !ok || auth == nil {
		return nil, errors.New("selected authentication entry missing")
	}
	if auth.Exec != nil || auth.AuthProvider != nil {
		return nil, errors.New("credential plugins require a separately admitted authentication profile")
	}
	snapshot, err := captureKubernetesConfig(raw, kubeconfig, contextName, namespace)
	if err != nil {
		return nil, err
	}
	config, err := clientcmd.RESTConfigFromKubeConfig(snapshot)
	if err != nil {
		return nil, errors.New("captured Kubernetes configuration is unusable")
	}
	config.Timeout = 30 * time.Second
	config.UserAgent = "cinderlock"
	config.Proxy = http.ProxyURL(nil)
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.New("captured Kubernetes transport is unusable")
	}
	return &Kubernetes{Client: client, Config: config, Namespace: namespace, Release: release, Kubeconfig: kubeconfig, Context: contextName, configSnapshot: snapshot}, nil
}

func fingerprint(value any) string {
	b, _ := json.Marshal(value)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func TargetIdentity(server, namespaceUID string) string {
	return fingerprint(struct{ Server, NamespaceUID string }{server, namespaceUID})
}

func (e *Engine) TargetIdentity(ctx context.Context) (string, error) {
	ns, err := e.Kube.Client.CoreV1().Namespaces().Get(ctx, e.Site.Spec.Namespace, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if e.Kube.Config == nil {
		return "", errors.New("target REST configuration is unavailable")
	}
	id := TargetIdentity(e.Kube.Config.Host, string(ns.UID))
	if e.Site.Spec.NamespaceUID != "" && e.Site.Spec.NamespaceUID != string(ns.UID) || e.Site.Spec.ClusterID != "" && e.Site.Spec.ClusterID != id {
		return "", spec.Err(11, "observed target identity differs from customer Site pin")
	}
	return id, nil
}

func (k *Kubernetes) Observe(ctx context.Context) (Observation, error) {
	ns, err := k.Client.CoreV1().Namespaces().Get(ctx, k.Namespace, metav1.GetOptions{})
	if err != nil {
		return Observation{}, fmt.Errorf("inspect namespace: %w", err)
	}
	server := ""
	if k.Config != nil {
		server = k.Config.Host
	}
	o := Observation{TargetID: TargetIdentity(server, string(ns.UID)), NamespaceUID: string(ns.UID), Server: server, Resources: []Resource{}, GPUs: map[string]string{}, GPUEvidence: "not_tested", Findings: []string{}}
	version, err := k.Client.Discovery().ServerVersion()
	if err == nil {
		o.KubernetesVersion = version.GitVersion
	} else {
		o.Findings = append(o.Findings, "Kubernetes server version unavailable")
	}
	selector := "app.kubernetes.io/instance=" + k.Release
	ds, err := k.Client.AppsV1().Deployments(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return o, fmt.Errorf("inspect deployments: %w", err)
	}
	for _, d := range ds.Items {
		if err := checkOwner(d.ObjectMeta, k.Release); err != nil {
			return o, err
		}
		o.Resources = append(o.Resources, Resource{Kind: "Deployment", Name: d.Name, UID: string(d.UID), Fingerprint: fingerprint(d.Spec), Ready: deploymentRolledOut(&d)})
	}
	sts, err := k.Client.AppsV1().StatefulSets(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return o, fmt.Errorf("inspect statefulsets: %w", err)
	}
	for _, s := range sts.Items {
		if err := checkOwner(s.ObjectMeta, k.Release); err != nil {
			return o, err
		}
		o.Resources = append(o.Resources, Resource{Kind: "StatefulSet", Name: s.Name, UID: string(s.UID), Fingerprint: fingerprint(s.Spec), Ready: s.Status.ObservedGeneration >= s.Generation && s.Status.ReadyReplicas >= replicas(s.Spec.Replicas)})
	}
	cms, err := k.Client.CoreV1().ConfigMaps(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return o, fmt.Errorf("inspect application configmaps: %w", err)
	}
	for _, c := range cms.Items {
		if err := checkOwner(c.ObjectMeta, k.Release); err != nil {
			return o, err
		}
		o.Resources = append(o.Resources, Resource{Kind: "ConfigMap", Name: c.Name, UID: string(c.UID), Fingerprint: fingerprint(struct {
			Data       map[string]string
			BinaryData map[string][]byte
		}{c.Data, c.BinaryData}), Ready: true})
	}
	services, err := k.Client.CoreV1().Services(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return o, fmt.Errorf("inspect application services: %w", err)
	}
	for _, service := range services.Items {
		if err := checkOwner(service.ObjectMeta, k.Release); err != nil {
			return o, err
		}
		o.Resources = append(o.Resources, Resource{Kind: "Service", Name: service.Name, UID: string(service.UID), Fingerprint: fingerprint(service.Spec), Ready: true})
	}
	pvcs, err := k.Client.CoreV1().PersistentVolumeClaims(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return o, fmt.Errorf("inspect application volumes: %w", err)
	}
	for _, pvc := range pvcs.Items {
		if err := checkOwner(pvc.ObjectMeta, k.Release); err != nil {
			return o, err
		}
		o.Resources = append(o.Resources, Resource{Kind: "PersistentVolumeClaim", Name: pvc.Name, UID: string(pvc.UID), Fingerprint: fingerprint(pvc.Spec), Ready: pvc.Status.Phase == corev1.ClaimBound})
	}
	secrets, err := k.Client.CoreV1().Secrets(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return o, fmt.Errorf("inspect application Secret metadata: %w", err)
	}
	for _, secret := range secrets.Items {
		if err := checkOwner(secret.ObjectMeta, k.Release); err != nil {
			return o, err
		}
		o.Resources = append(o.Resources, Resource{Kind: "Secret", Name: secret.Name, UID: string(secret.UID), Fingerprint: fingerprint(struct{ UID, Version string }{string(secret.UID), secret.ResourceVersion}), Ready: true})
	}
	return o, nil
}

func (k *Kubernetes) ObserveGPUs(ctx context.Context) (map[string]string, error) {
	nodes, err := k.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("GPU node facts unavailable: %w", err)
	}
	out := map[string]string{}
	for _, n := range nodes.Items {
		if q, ok := n.Status.Allocatable[corev1.ResourceName("nvidia.com/gpu")]; ok {
			out[n.Name] = q.String()
		}
	}
	return out, nil
}

func replicas(n *int32) int32 {
	if n == nil {
		return 1
	}
	return *n
}

func deploymentRolledOut(d *appsv1.Deployment) bool {
	desired := replicas(d.Spec.Replicas)
	return d.Status.ObservedGeneration >= d.Generation && d.Status.UpdatedReplicas == desired && d.Status.ReadyReplicas >= desired && d.Status.AvailableReplicas >= desired && d.Status.Replicas == desired && (d.Status.TerminatingReplicas == nil || *d.Status.TerminatingReplicas == 0)
}

func checkOwner(meta metav1.ObjectMeta, release string) error {
	for key := range meta.Labels {
		if strings.HasPrefix(key, "argocd.argoproj.io/") || strings.HasPrefix(key, "helm.toolkit.fluxcd.io/") || strings.HasPrefix(key, "kustomize.toolkit.fluxcd.io/") {
			return fmt.Errorf("resource %s has a competing GitOps owner", meta.Name)
		}
	}
	if owner := meta.Annotations["meta.helm.sh/release-name"]; owner != "" && owner != release {
		return fmt.Errorf("resource %s belongs to another Helm release", meta.Name)
	}
	return nil
}

func RestartSpec(d *appsv1.Deployment, runID string) *appsv1.Deployment {
	copy := d.DeepCopy()
	if copy.Spec.Template.Annotations == nil {
		copy.Spec.Template.Annotations = map[string]string{}
	}
	copy.Spec.Template.Annotations["cinderlock.dev/restart-run"] = runID
	return copy
}
