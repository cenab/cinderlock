package engine

import (
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
	authorizationv1 "k8s.io/api/authorization/v1"
)

// The phase snapshot contains only the observer's explicitly selected reads.
func (e *Engine) gitOpsPermissionReads(p spec.Plan) ([]authorizationv1.ResourceAttributes, error) {
	reads := []authorizationv1.ResourceAttributes{}
	add := func(group, resource, name string) {
		reads = append(reads, authorizationv1.ResourceAttributes{Namespace: e.Site.Spec.Namespace, Group: group, Resource: resource, Name: name, Verb: "get"})
	}
	// Models and dedicated fixtures also exclude pending native controllers.
	if len(p.Operations) > 0 || p.GitOps != nil && p.GitOps.Preparation != nil {
		for _, scope := range []struct{ group, resource string }{{"apps", "deployments"}, {"apps", "statefulsets"}, {"apps", "daemonsets"}, {"apps", "replicasets"}, {"batch", "jobs"}, {"batch", "cronjobs"}, {"", "replicationcontrollers"}, {"", "podtemplates"}} {
			reads = append(reads, authorizationv1.ResourceAttributes{Namespace: e.Site.Spec.Namespace, Group: scope.group, Resource: scope.resource, Verb: "list"})
		}
	}
	// Selected Helm history absence; stateless checks need no consumer Pod list.
	reads = append(reads, authorizationv1.ResourceAttributes{Namespace: e.Site.Spec.Namespace, Resource: "secrets", Verb: "list"})
	if len(p.Operations) > 0 || p.GitOps != nil && p.GitOps.Preparation != nil {
		reads = append(reads, authorizationv1.ResourceAttributes{Namespace: e.Site.Spec.Namespace, Resource: "pods", Verb: "list"})
	}
	if p.GitOps != nil && p.GitOps.Contract != nil {
		c := p.GitOps.Contract
		reads = append(reads, authorizationv1.ResourceAttributes{Namespace: c.Namespace, Group: "argoproj.io", Resource: "applications", Name: c.Name, Verb: "get"})
	}
	if p.GitOps != nil && p.GitOps.Preparation != nil {
		add("apps", "replicasets", "")
		add("", "pods", "")
	}
	for _, resource := range p.Snapshot.Resources {
		if resource.Kind == "Application" {
			continue
		}
		selected, ok := permissionResources[resource.Kind]
		if !ok || resource.Namespace != e.Site.Spec.Namespace || resource.Name == "" {
			return nil, spec.Err(16, "GitOps observation permission scope escapes its selected resource profile")
		}
		add(selected.group, selected.resource, resource.Name)
	}
	for _, fact := range p.Snapshot.Facts {
		switch {
		case strings.HasPrefix(fact.Name, "gitops/prepared-volume/"):
			add("", "persistentvolumeclaims", strings.TrimPrefix(fact.Name, "gitops/prepared-volume/"))
		case strings.HasPrefix(fact.Name, "secret/image-pull-"):
			add("", "secrets", strings.TrimPrefix(fact.Name, "secret/image-pull-"))
		case strings.HasPrefix(fact.Name, "secret/"):
			id := strings.TrimPrefix(fact.Name, "secret/")
			ref, ok := e.Site.Spec.SecretRefs[id]
			if !ok || ref.Namespace != "" && ref.Namespace != e.Site.Spec.Namespace {
				return nil, spec.Err(16, "GitOps selected credential read is outside Site scope")
			}
			if ref.File == "" {
				add("", "secrets", ref.Name)
			}
		case strings.HasPrefix(fact.Name, "gitops/secret/"):
			name, _, _ := strings.Cut(strings.TrimPrefix(fact.Name, "gitops/secret/"), "/")
			add("", "secrets", name)
		case strings.HasPrefix(fact.Name, "gitops/image-pull/"):
			add("", "secrets", strings.TrimPrefix(fact.Name, "gitops/image-pull/"))
		}
	}
	return reads, nil
}
