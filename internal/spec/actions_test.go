package spec

import (
	"slices"
	"testing"
)

func TestPlanActionsDeclaresOrderedUniqueCapabilities(t *testing.T) {
	for _, test := range []struct {
		name string
		plan Plan
		want []string
	}{
		{"empty", Plan{}, nil},
		{"operations", Plan{Operations: []Operation{{Type: "restart"}, {Type: "helm"}, {Type: "restart"}}}, []string{"restart", "helm"}},
		{"authored-job", Plan{Checks: []Check{{Type: "job"}}}, []string{"job"}},
		{"ordinary-http", Plan{Checks: []Check{{Type: "http", URL: "http://app/"}}}, []string{"job"}},
		{"endpoint-TLS", Plan{Checks: []Check{{Type: "endpoint", URL: "https://registry.internal/"}}}, []string{"job", "endpoint-probe"}},
		{"invalid-endpoint", Plan{Checks: []Check{{Type: "endpoint", URL: "invalid"}}}, []string{"job", "endpoint-probe"}},
		{"artifacts", Plan{Header: NewHeader("ArtifactsPlan"), Operations: []Operation{{Type: "import"}}}, []string{"import", "gitops-stage"}},
		{"prepare", Plan{Header: NewHeader("GitOpsPreparePlan"), Operations: []Operation{{Type: "seed"}}, Checks: []Check{{Type: "job"}}}, []string{"seed", "job", "gitops-prepare"}},
		{"checks-only-phase", Plan{Header: NewHeader("GitOpsChecksPlan")}, []string{"gitops-check", "gitops-observe"}},
		{"combined", Plan{Header: NewHeader("GitOpsChecksPlan"), Operations: []Operation{{Type: "job"}, {Type: "helm"}, {Type: "job"}}, Checks: []Check{{Type: "job"}, {Type: "endpoint", URL: "https://registry.internal/"}, {Type: "endpoint", URL: "http://registry.internal/"}, {Type: "endpoint", URL: "http://registry.internal/"}}}, []string{"job", "helm", "endpoint-probe", "endpoint-http", "gitops-check", "gitops-observe"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := PlanActions(test.plan); !slices.Equal(got, test.want) {
				t.Fatalf("capabilities = %v, want %v", got, test.want)
			}
		})
	}
}
