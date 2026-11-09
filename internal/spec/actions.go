package spec

// PlanActions is the ordered capability set shared by approval and admission.
func PlanActions(p Plan) []string {
	actions := []string{}
	add := func(action string) {
		if !containsString(actions, action) {
			actions = append(actions, action)
		}
	}
	for _, operation := range p.Operations {
		add(operation.Type)
	}
	if len(p.Checks) > 0 {
		add("job")
	}
	for _, action := range EndpointActions(p.Checks) {
		add(action)
	}
	switch p.Kind {
	case "ArtifactsPlan":
		add("gitops-stage")
	case "GitOpsPreparePlan":
		add("gitops-prepare")
	case "GitOpsDataPlan", "GitOpsDataChecksPlan", "GitOpsDataRecoveryPlan":
		add("gitops-data")
		add("gitops-observe")
	case "GitOpsChecksPlan":
		add("gitops-check")
		add("gitops-observe")
	}
	return actions
}
