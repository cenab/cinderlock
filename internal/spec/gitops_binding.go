package spec

// GitOpsRunReference pins one completed phase's exact local journal evidence.
type GitOpsRunReference struct {
	RunID        string `json:"runID"`
	PlanDigest   string `json:"planDigest"`
	ResultDigest string `json:"resultDigest"`
}

// GitOpsPlanBinding retains reviewed input identities independently of run authority.
type GitOpsPlanBinding struct {
	Data         *GitOpsDataBinding     `json:"data,omitempty"`
	ManifestPath string                 `json:"manifestPath"`
	Staging      GitOpsRunReference     `json:"staging"`
	Preparation  *GitOpsRunReference    `json:"preparation,omitempty"`
	Contract     *GitOpsProfileContract `json:"contract,omitempty"`
	Repository   string                 `json:"repository,omitempty"`
}

// GitOpsDataBinding pins one mutable claim and exact historical phase facts.
type GitOpsDataBinding struct {
	PVC                  string              `json:"pvc"`
	UID                  string              `json:"uid"`
	Revision             string              `json:"revision"`
	BackupRef            string              `json:"backupRef,omitempty"`
	Initial              bool                `json:"initial,omitempty"`
	Previous             *GitOpsRunReference `json:"previous,omitempty"`
	PreviousManifestPath string              `json:"previousManifestPath,omitempty"`
	Predecessor          *GitOpsRunReference `json:"predecessor,omitempty"`
	Recovery             string              `json:"recovery,omitempty"`
}
