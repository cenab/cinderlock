package spec

import "k8s.io/apimachinery/pkg/util/validation"

// GitOpsDataProcedures names signed Jobs; their completion is not storage fencing.
type GitOpsDataProcedures struct {
	PVC     string `json:"pvc" yaml:"pvc"`
	Quiesce string `json:"quiesce,omitempty" yaml:"quiesce,omitempty"`
	Backup  string `json:"backup,omitempty" yaml:"backup,omitempty"`
	Resume  string `json:"resume,omitempty" yaml:"resume,omitempty"`
}

func validateGitOpsData(r Release) error {
	var declared *GitOpsDataProcedures
	if r.Spec.Deployment.GitOps != nil {
		declared = r.Spec.Deployment.GitOps.Data
	}
	validate := func(c *GitOpsDataProcedures, operations []Operation) error {
		if r.Spec.Deployment.Type != "gitops" || r.Spec.Deployment.GitOps == nil || r.Spec.Deployment.GitOps.Owner != "argocd" || len(validation.IsDNS1123Subdomain(c.PVC)) != 0 {
			return Err(2, "GitOps data procedures require Argo ownership and an explicit namespaced claim")
		}
		roles := map[string]string{}
		for _, role := range []struct{ id, kind string }{{c.Quiesce, "job"}, {c.Backup, "backup"}, {c.Resume, "job"}} {
			if role.id == "" {
				continue
			}
			if !identifier.MatchString(role.id) || roles[role.id] != "" {
				return Err(2, "GitOps data procedure roles must name distinct signed operations")
			}
			roles[role.id] = role.kind
		}
		for _, op := range operations {
			if want, exists := roles[op.ID]; exists {
				if op.Type != want {
					return Err(2, "GitOps data procedure role has the wrong operation type: %s", op.ID)
				}
				delete(roles, op.ID)
			}
			if op.Type == "seed" && op.PVC == c.PVC {
				return Err(2, "mutable data claims cannot be native artifact seeds")
			}
			if op.PVC != "" && op.Type != "seed" && op.PVC != c.PVC {
				return Err(2, "GitOps data procedures may mount only their declared mutable claim")
			}
		}
		if len(roles) != 0 {
			return Err(2, "GitOps data procedure role references a missing operation")
		}
		return nil
	}
	if declared != nil {
		for _, transition := range r.Spec.Transitions {
			if transition.ToDataRevision == "" || transition.FromRelease != "install" && (transition.FromDataRevision == "" || declared.Quiesce == "" || declared.Backup == "" || declared.Resume == "") {
				return Err(2, "GitOps data transitions need explicit source/target revisions and upgrade quiesce, backup and resume procedures")
			}
		}
		if err := validate(declared, r.Spec.Operations); err != nil {
			return err
		}
	}
	for _, recovery := range r.Spec.Recovery {
		if recovery.GitOpsData == nil {
			continue
		}
		if declared == nil || recovery.GitOpsData.PVC != declared.PVC || recovery.GitOpsData.Quiesce == "" || recovery.GitOpsData.Resume == "" {
			return Err(2, "GitOps data recovery needs the same claim and explicit quiesce/resume operations")
		}
		if err := validate(recovery.GitOpsData, recovery.Operations); err != nil {
			return err
		}
	}
	return nil
}
