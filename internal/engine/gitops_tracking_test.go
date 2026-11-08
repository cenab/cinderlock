package engine

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestObserveGitOpsProfileControllerNamespace(t *testing.T) {
	for _, name := range []string{"controller-namespace", "missing", "empty", "malformed", "other-namespace-plain-tracking", "other-namespace-native-tracking"} {
		t.Run(name, func(t *testing.T) {
			f := newProfileFixture(t)
			profileSet(t, f.application, f.contract.Namespace, "status", "controllerNamespace")
			switch name {
			case "missing":
				unstructured.RemoveNestedField(f.application.Object, "status", "controllerNamespace")
			case "empty":
				profileSet(t, f.application, "", "status", "controllerNamespace")
			case "malformed":
				profileSet(t, f.application, false, "status", "controllerNamespace")
			case "other-namespace-plain-tracking", "other-namespace-native-tracking":
				f.contract.Namespace = "team"
				f.application.SetNamespace("team")
				if name == "other-namespace-native-tracking" {
					for _, object := range f.live {
						annotations := object.GetAnnotations()
						annotations["argocd.argoproj.io/tracking-id"] = strings.Replace(annotations["argocd.argoproj.io/tracking-id"], f.contract.Name+":", "team_"+f.contract.Name+":", 1)
						object.SetAnnotations(annotations)
					}
				}
			}
			f.seed(t)
			if name != "controller-namespace" {
				f.denied(t, "CONTROLLER_MISMATCH")
				return
			}
			o, err := f.observe()
			if err != nil || !o.Ready {
				t.Fatalf("native same-namespace Application rejected: %v %#v", err, o.Findings)
			}
			f.assertReadOnly(t)
		})
	}
}
