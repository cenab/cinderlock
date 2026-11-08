package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (e *Engine) Inspect(ctx context.Context) (spec.TargetSnapshot, error) {
	o, err := e.Kube.Observe(ctx)
	if err != nil {
		return spec.TargetSnapshot{}, err
	}
	s := spec.TargetSnapshot{Header: spec.NewHeader("TargetSnapshot"), SiteID: e.Site.Metadata.Name, TargetID: o.TargetID, NamespaceUID: o.NamespaceUID, ObservedAt: spec.Now(), DataRevision: e.Site.Spec.DataRevision, Resources: []spec.ResourceFact{}, Facts: o.Facts, Findings: []spec.Finding{}}
	if o.TargetID == "" || o.NamespaceUID == "" {
		e.finalizeInspection(&s)
		return s, nil
	}
	if e.Site.Spec.NamespaceUID != "" && e.Site.Spec.NamespaceUID != o.NamespaceUID {
		return s, spec.Err(11, "namespace UID differs from site pin")
	}
	if e.Site.Spec.ClusterID != "" && e.Site.Spec.ClusterID != o.TargetID {
		return s, spec.Err(11, "target identity differs from site pin")
	}
	for _, r := range o.Resources {
		s.Resources = append(s.Resources, spec.ResourceFact{Kind: r.Kind, Name: r.Name, Namespace: e.Site.Spec.Namespace, UID: r.UID, Fingerprint: r.Fingerprint})
		s.Facts = append(s.Facts, spec.Fact{Name: "readiness/" + r.Kind + "/" + r.Name, Value: fmt.Sprint(r.Ready), Status: "known", Source: "Kubernetes resource status"})
	}
	gp, err := e.Kube.ObserveGPUs(ctx)
	if err != nil {
		s.Facts = append(s.Facts, spec.Fact{Name: "nvidia.allocatable", Status: observationStatus(err), Source: "node authorization/discovery"})
	} else {
		var total int64
		for _, count := range gp {
			var n int64
			_, _ = fmt.Sscan(count, &n)
			total += n
		}
		status := "known"
		if total == 0 {
			status = "absent"
		}
		s.Facts = append(s.Facts, spec.Fact{Name: "nvidia.allocatable", Value: fmt.Sprint(total), Status: status, Source: "Kubernetes node allocatable; not hardware qualification"})
	}
	if err := e.inspectSecrets(ctx, &s); err != nil {
		return s, err
	}
	sort.Slice(s.Resources, func(i, j int) bool {
		return s.Resources[i].Kind+"/"+s.Resources[i].Name < s.Resources[j].Kind+"/"+s.Resources[j].Name
	})
	rev, version, values, err := e.helmState(ctx)
	release := spec.Fact{Name: "helm.release", Status: observationStatus(err), Source: "Helm history and effective values"}
	if err != nil {
		if release.Status == "absent" {
			release.Status = "unavailable"
		}
		if spec.ExitCode(err) == 13 {
			release.Status = "stale"
		}
		s.Findings = append(s.Findings, spec.Finding{Code: "HELM_STATE_" + strings.ToUpper(release.Status), Severity: "blocker", Message: "Helm release state is " + release.Status, Source: release.Source})
	} else {
		s.HelmRevision, s.InstalledVersion = rev, version
		release.Value = version
		if version == "" {
			release.Status = "absent"
		}
		s.EffectiveConfigDigest, err = e.privateFingerprint(values)
		if err != nil {
			return s, err
		}
	}
	s.Facts = append(s.Facts, release)
	if s.DataRevision != "" {
		s.Facts = append(s.Facts, spec.Fact{Name: "application.dataRevision", Value: s.DataRevision, Status: "asserted", Source: "customer Site assertion; vendor operation must enforce its own schema precondition"})
	}
	e.finalizeInspection(&s)
	return s, nil
}

func (e *Engine) finalizeInspection(s *spec.TargetSnapshot) {
	present := map[string]bool{}
	for _, fact := range s.Facts {
		present[fact.Name] = true
	}
	names := []string{"kubernetes.api", "namespace.identity", "kubernetes.version", "helm.release", "nvidia.allocatable"}
	for _, kind := range []string{"Deployment", "StatefulSet", "ConfigMap", "Service", "PersistentVolumeClaim", "Secret"} {
		names = append(names, "inventory/"+kind)
	}
	for name := range e.Site.Spec.SecretRefs {
		names = append(names, "secret/"+name)
	}
	for _, name := range e.Site.Spec.ImagePullSecrets {
		names = append(names, "secret/image-pull-"+name)
	}
	for _, name := range names {
		if !present[name] {
			s.Facts = append(s.Facts, spec.Fact{Name: name, Status: "unknown", Source: "read was not completed"})
		}
	}
	sort.Slice(s.Facts, func(i, j int) bool { return s.Facts[i].Name < s.Facts[j].Name })
	for _, fact := range s.Facts {
		inventory := strings.HasPrefix(fact.Name, "inventory/")
		required := inventory || fact.Name == "kubernetes.api" || fact.Name == "namespace.identity" || fact.Name == "helm.release"
		valid := fact.Status == "known" || fact.Status == "absent" && (inventory && fact.Value == "0" || fact.Name == "helm.release")
		if required && !valid {
			s.Findings = append(s.Findings, spec.Finding{Code: "TARGET_FACT_" + strings.ToUpper(fact.Status), Severity: "blocker", Message: fact.Name + " is " + fact.Status, Source: fact.Source})
		}
	}
}

func targetObservationError(s spec.TargetSnapshot) error {
	if s.TargetID == "" || s.NamespaceUID == "" {
		return spec.Err(10, "target identity is not established")
	}
	for _, finding := range s.Findings {
		if finding.Severity == "blocker" {
			return spec.Err(10, "required target observation is incomplete: %s", finding.Message)
		}
	}
	return nil
}

func (e *Engine) inspectSecrets(ctx context.Context, s *spec.TargetSnapshot) error {
	type binding struct {
		secret *corev1.Secret
		refs   map[string]string
	}
	bindings := map[types.NamespacedName]*binding{}
	bind := func(name string) *binding {
		id := types.NamespacedName{Namespace: e.Site.Spec.Namespace, Name: name}
		if bindings[id] == nil {
			bindings[id] = &binding{refs: map[string]string{}}
		}
		return bindings[id]
	}
	for name, ref := range e.Site.Spec.SecretRefs {
		if ref.File != "" {
			value, err := e.privateFileFingerprint(ref.File)
			fact := spec.Fact{Name: "secret/" + name, Status: observationStatus(err), Source: "local private-file reference"}
			if err == nil {
				fact.Value, fact.Status = value, "known"
			}
			s.Facts = append(s.Facts, fact)
			continue
		}
		if ref.Namespace != "" && ref.Namespace != e.Site.Spec.Namespace {
			return spec.Err(16, "cross-namespace secret reference is unsupported")
		}
		bind(ref.Name).refs["secret/"+name] = ref.Key
	}
	for _, name := range e.Site.Spec.ImagePullSecrets {
		if _, exists := e.Site.Spec.SecretRefs["image-pull-"+name]; exists {
			return spec.Err(16, "image pull Secret fact name collides with a Site secret reference")
		}
		bind(name).refs["secret/image-pull-"+name] = ""
	}
	secrets, err := e.Kube.Client.CoreV1().Secrets(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/instance=" + e.Site.Spec.ReleaseName})
	if err != nil {
		s.Facts = append(s.Facts, inventoryFact("Secret", 0, err))
		secrets = &corev1.SecretList{}
	} else {
		s.Facts = append(s.Facts, inventoryFact("Secret", len(secrets.Items), nil))
	}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		if err := checkOwner(&secret.ObjectMeta, e.Site.Spec.ReleaseName, nil); err != nil {
			return err
		}
		bind(secret.Name).secret = secret
	}
	for id, binding := range bindings {
		secret := binding.secret
		managed := secret != nil
		if !managed {
			secret, err = e.Kube.Client.CoreV1().Secrets(id.Namespace).Get(ctx, id.Name, metav1.GetOptions{})
			if err != nil {
				for name := range binding.refs {
					s.Facts = append(s.Facts, spec.Fact{Name: name, Status: observationStatus(err), Source: "Kubernetes Secret access"})
				}
				continue
			}
		}
		// Managed Secrets bind every key because workloads may consume undeclared keys.
		data := map[string][]byte{}
		full := managed || len(binding.refs) == 0
		for _, key := range binding.refs {
			if key == "" {
				full = true
			} else if value, ok := secret.Data[key]; ok {
				data[key] = value
			}
		}
		if full {
			data = secret.Data
		}
		value, err := e.secretFingerprint(secret, data)
		if err != nil {
			return err
		}
		if managed {
			body, err := spec.Canonical(resourceBinding(secret.ObjectMeta, value))
			if err != nil {
				return errors.New("cannot encode Secret ownership binding")
			}
			owned, err := e.privateFingerprint(append([]byte("cinderlock.inspection-secret-ownership.v1\x00"), body...))
			if err != nil {
				return errors.New("cannot fingerprint Secret ownership binding")
			}
			s.Resources = append(s.Resources, spec.ResourceFact{Kind: "Secret", Namespace: id.Namespace, Name: id.Name, UID: string(secret.UID), Fingerprint: owned})
			s.Facts = append(s.Facts, spec.Fact{Name: "readiness/Secret/" + id.Name, Value: "true", Status: "known", Source: "Kubernetes resource status"})
		}
		for name, key := range binding.refs {
			fact := spec.Fact{Name: name, Value: value, Status: "known", Source: "Kubernetes Secret private binding"}
			if _, ok := secret.Data[key]; key != "" && !ok {
				fact.Value, fact.Status, fact.Source = "", "absent", "referenced Kubernetes Secret key is absent"
			}
			s.Facts = append(s.Facts, fact)
		}
	}
	return nil
}
