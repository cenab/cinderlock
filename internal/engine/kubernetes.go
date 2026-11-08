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
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/spec"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	TargetID     string      `json:"targetID"`
	NamespaceUID string      `json:"namespaceUID"`
	Server       string      `json:"server"`
	Resources    []Resource  `json:"resources"`
	Facts        []spec.Fact `json:"facts"`
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

func gitOpsOwnerKey(key string) bool {
	return strings.HasPrefix(key, "argocd.argoproj.io/") || strings.HasPrefix(key, "helm.toolkit.fluxcd.io/") || strings.HasPrefix(key, "kustomize.toolkit.fluxcd.io/") || strings.HasPrefix(key, "fluxcd.io/")
}

func resourceBinding(meta metav1.ObjectMeta, value any) any {
	markers := map[string]string{
		"manager":   meta.Labels["app.kubernetes.io/managed-by"],
		"release":   meta.Annotations["meta.helm.sh/release-name"],
		"namespace": meta.Annotations["meta.helm.sh/release-namespace"],
	}
	for key, value := range meta.Labels {
		if gitOpsOwnerKey(key) {
			markers["label/"+key] = value
		}
	}
	for key, value := range meta.Annotations {
		if gitOpsOwnerKey(key) {
			markers["annotation/"+key] = value
		}
	}
	owners := slices.Clone(meta.OwnerReferences)
	sort.Slice(owners, func(i, j int) bool { return owners[i].UID < owners[j].UID })
	return struct {
		Markers map[string]string       `json:"markers"`
		Owners  []metav1.OwnerReference `json:"owners,omitempty"`
		Value   any                     `json:"value"`
	}{markers, owners, value}
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

func observationStatus(err error) string {
	switch {
	case err == nil:
		return "known"
	case apierrors.IsNotFound(err), errors.Is(err, os.ErrNotExist):
		return "absent"
	case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err), errors.Is(err, os.ErrPermission):
		return "denied"
	case apierrors.IsResourceExpired(err), apierrors.IsGone(err):
		return "stale"
	default:
		return "unavailable"
	}
}

func inventoryFact(kind string, count int, err error) spec.Fact {
	fact := spec.Fact{Name: "inventory/" + kind, Status: observationStatus(err), Source: "Kubernetes release-selector list"}
	if err == nil {
		fact.Value = strconv.Itoa(count)
		if count == 0 {
			fact.Status = "absent"
		}
	}
	return fact
}

func (k *Kubernetes) Observe(ctx context.Context) (Observation, error) {
	o := Observation{Resources: []Resource{}, Facts: []spec.Fact{}}
	if k.Config != nil {
		o.Server = k.Config.Host
	}
	api := spec.Fact{Name: "kubernetes.api", Value: o.Server, Status: "known", Source: "explicit Kubernetes REST configuration"}
	if o.Server == "" {
		api.Status = "unavailable"
	}
	o.Facts = append(o.Facts, api)
	ns, err := k.Client.CoreV1().Namespaces().Get(ctx, k.Namespace, metav1.GetOptions{})
	namespace := spec.Fact{Name: "namespace.identity", Status: observationStatus(err), Source: "Kubernetes namespace UID"}
	if err == nil {
		namespace.Value = string(ns.UID)
		if namespace.Value == "" {
			namespace.Status = "unavailable"
		}
	}
	o.Facts = append(o.Facts, namespace)
	if api.Status != "known" || namespace.Status != "known" {
		return o, nil
	}
	o.NamespaceUID = namespace.Value
	o.TargetID = TargetIdentity(o.Server, o.NamespaceUID)
	version, err := k.Client.Discovery().ServerVersion()
	fact := spec.Fact{Name: "kubernetes.version", Status: observationStatus(err), Source: "Kubernetes discovery"}
	if err == nil && version != nil && version.GitVersion != "" {
		fact.Value = version.GitVersion
	} else if err == nil {
		fact.Status = "unavailable"
	}
	o.Facts = append(o.Facts, fact)
	selector := "app.kubernetes.io/instance=" + k.Release
	ds, err := k.Client.AppsV1().Deployments(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		o.Facts = append(o.Facts, inventoryFact("Deployment", 0, err))
		ds = &appsv1.DeploymentList{}
	} else {
		o.Facts = append(o.Facts, inventoryFact("Deployment", len(ds.Items), nil))
	}
	for _, d := range ds.Items {
		if err := checkOwner(&d.ObjectMeta, k.Release, nil); err != nil {
			return o, err
		}
		o.Resources = append(o.Resources, Resource{Kind: "Deployment", Name: d.Name, UID: string(d.UID), Fingerprint: fingerprint(resourceBinding(d.ObjectMeta, d.Spec)), Ready: deploymentRolledOut(&d)})
	}
	parents := map[types.UID]metav1.OwnerReference{}
	sts, err := k.Client.AppsV1().StatefulSets(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		o.Facts = append(o.Facts, inventoryFact("StatefulSet", 0, err))
		sts = &appsv1.StatefulSetList{}
	} else {
		o.Facts = append(o.Facts, inventoryFact("StatefulSet", len(sts.Items), nil))
	}
	for _, s := range sts.Items {
		if err := checkOwner(&s.ObjectMeta, k.Release, nil); err != nil {
			return o, err
		}
		if s.UID != "" {
			parents[s.UID] = metav1.OwnerReference{APIVersion: "apps/v1", Kind: "StatefulSet", Name: s.Name, UID: s.UID}
		}
		o.Resources = append(o.Resources, Resource{Kind: "StatefulSet", Name: s.Name, UID: string(s.UID), Fingerprint: fingerprint(resourceBinding(s.ObjectMeta, s.Spec)), Ready: s.Status.ObservedGeneration >= s.Generation && s.Status.ReadyReplicas >= replicas(s.Spec.Replicas)})
	}
	cms, err := k.Client.CoreV1().ConfigMaps(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		o.Facts = append(o.Facts, inventoryFact("ConfigMap", 0, err))
		cms = &corev1.ConfigMapList{}
	} else {
		o.Facts = append(o.Facts, inventoryFact("ConfigMap", len(cms.Items), nil))
	}
	for _, c := range cms.Items {
		if err := checkOwner(&c.ObjectMeta, k.Release, nil); err != nil {
			return o, err
		}
		o.Resources = append(o.Resources, Resource{Kind: "ConfigMap", Name: c.Name, UID: string(c.UID), Fingerprint: fingerprint(resourceBinding(c.ObjectMeta, struct {
			Data       map[string]string
			BinaryData map[string][]byte
		}{c.Data, c.BinaryData})), Ready: true})
	}
	services, err := k.Client.CoreV1().Services(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		o.Facts = append(o.Facts, inventoryFact("Service", 0, err))
		services = &corev1.ServiceList{}
	} else {
		o.Facts = append(o.Facts, inventoryFact("Service", len(services.Items), nil))
	}
	for _, service := range services.Items {
		if err := checkOwner(&service.ObjectMeta, k.Release, nil); err != nil {
			return o, err
		}
		o.Resources = append(o.Resources, Resource{Kind: "Service", Name: service.Name, UID: string(service.UID), Fingerprint: fingerprint(resourceBinding(service.ObjectMeta, service.Spec)), Ready: true})
	}
	pvcs, err := k.Client.CoreV1().PersistentVolumeClaims(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		o.Facts = append(o.Facts, inventoryFact("PersistentVolumeClaim", 0, err))
		pvcs = &corev1.PersistentVolumeClaimList{}
	} else {
		o.Facts = append(o.Facts, inventoryFact("PersistentVolumeClaim", len(pvcs.Items), nil))
	}
	for _, pvc := range pvcs.Items {
		var parent *metav1.OwnerReference
		for _, owner := range pvc.OwnerReferences {
			if owner.Controller != nil && *owner.Controller {
				if expected, ok := parents[owner.UID]; ok {
					parent = &expected
				}
			}
		}
		scope := "read_retain"
		source := "observed PVC ownership scope; read/retain grants no object mutation or deletion rights"
		if parent != nil {
			if checkOwner(&pvc.ObjectMeta, k.Release, parent) == nil {
				scope = "statefulset"
				source = "qualified StatefulSet " + parent.Name + " UID=" + string(parent.UID) + " in namespace " + k.Namespace
			}
		} else if checkOwner(&pvc.ObjectMeta, k.Release, nil) == nil {
			scope = "helm"
			source = "qualified Helm release " + k.Release + " in namespace " + k.Namespace
		}
		o.Facts = append(o.Facts, spec.Fact{Name: "ownership/PersistentVolumeClaim/" + pvc.Name, Value: scope, Status: "known", Source: source})
		o.Resources = append(o.Resources, Resource{Kind: "PersistentVolumeClaim", Name: pvc.Name, UID: string(pvc.UID), Fingerprint: fingerprint(resourceBinding(pvc.ObjectMeta, pvc.Spec)), Ready: pvc.Status.Phase == corev1.ClaimBound})
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

func checkOwner(meta metav1.Object, release string, parent *metav1.OwnerReference) error {
	labels, annotations, objectNamespace := meta.GetLabels(), meta.GetAnnotations(), meta.GetNamespace()
	if objectNamespace == "" {
		return spec.Err(16, "resource namespace is unavailable for ownership mapping")
	}
	for _, markers := range []map[string]string{labels, annotations} {
		for key := range markers {
			if gitOpsOwnerKey(key) {
				return spec.Err(16, "resource %s has a competing GitOps owner", meta.GetName())
			}
		}
	}
	controlled := false
	for _, owner := range meta.GetOwnerReferences() {
		if owner.Controller == nil || !*owner.Controller {
			continue
		}
		if parent == nil || parent.UID == "" || owner.UID != parent.UID || owner.Name != parent.Name || owner.Kind != parent.Kind || owner.APIVersion != parent.APIVersion {
			return spec.Err(16, "resource %s has unsupported active controller ownership", meta.GetName())
		}
		controlled = true
	}
	name, namespace, manager := annotations["meta.helm.sh/release-name"], annotations["meta.helm.sh/release-namespace"], labels["app.kubernetes.io/managed-by"]
	if parent != nil && controlled {
		if name != "" && name != release || namespace != "" && namespace != objectNamespace || manager != "" && manager != "Helm" {
			return spec.Err(16, "resource %s has ownership markers conflicting with its qualified parent", meta.GetName())
		}
		return nil
	}
	if name != release || namespace != objectNamespace || manager != "Helm" {
		return spec.Err(16, "resource %s is not explicitly owned by the selected Helm release", meta.GetName())
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
