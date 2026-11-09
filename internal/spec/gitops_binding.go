package spec

// GitOpsRunReference pins one completed phase's exact local journal evidence.
type GitOpsRunReference struct {
	RunID        string `json:"runID"`
	PlanDigest   string `json:"planDigest"`
	ResultDigest string `json:"resultDigest"`
}

// GitOpsPlanBinding retains reviewed input identities independently of run authority.
type GitOpsPlanBinding struct {
	ManifestPath string                 `json:"manifestPath"`
	Staging      GitOpsRunReference     `json:"staging"`
	Preparation  *GitOpsRunReference    `json:"preparation,omitempty"`
	Contract     *GitOpsProfileContract `json:"contract,omitempty"`
	Repository   string                 `json:"repository,omitempty"`
}
