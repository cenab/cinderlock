package engine

import (
	"reflect"
	"slices"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestGitOpsDataCutHonorsSignedTransitionAndProcedures(t *testing.T) {
	for _, change := range []string{"none", "initial", "ambiguous", "missing-dependency", "unbacked-mutation", "independent-mutation", "second-writer", "second-source", "early-fixture", "missing-quiesce", "cycle"} {
		t.Run(change, func(t *testing.T) {
			f := newProfileFixture(t)
			r := f.v.Index.Lock.Release
			r.Spec.Checks = []spec.Check{{ID: "workflow", Type: "job", Image: "runner", Command: []string{"/app/check"}, Domain: "workflow", Required: true, TimeoutSeconds: 5, Script: fixtureScript("workflow")}}
			r.Spec.Deployment.GitOps.Data = &spec.GitOpsDataProcedures{PVC: "data", Quiesce: "quiesce", Backup: "backup", Resume: "writes"}
			procedure := func(id, kind, dependency string) spec.Operation {
				return spec.Operation{ID: id, Type: kind, Image: "runner", Command: []string{"/app/" + id}, DependsOn: []string{dependency}, TimeoutSeconds: 5, Idempotent: true, Script: fixtureScript("workflow")}
			}
			r.Spec.Operations = []spec.Operation{{ID: "images", Type: "import"}, procedure("quiesce", "job", "images"), procedure("backup", "backup", "quiesce"), procedure("migration", "migrate", "backup"), {ID: "sync", Type: "gitops", DependsOn: []string{"migration"}}, procedure("writes", "job", "sync")}
			r.Spec.Transitions[0].Operations = []string{"writes", "sync", "migration", "backup", "quiesce", "images"}
			r.Spec.Transitions[0].FromDataRevision = "schema-1"
			r.Spec.Transitions[0].ToDataRevision = "schema-2"
			from := "1.0.0"
			switch change {
			case "initial":
				from = "install"
				r.Spec.Transitions[0].FromRelease = from
				r.Spec.Transitions[0].Operations = []string{"writes", "sync", "images"}
				r.Spec.Operations[4].DependsOn = []string{"images"}
			case "ambiguous":
				other := r.Spec.Transitions[0]
				other.ID = "other"
				r.Spec.Transitions = append(r.Spec.Transitions, other)
			case "missing-dependency":
				r.Spec.Transitions[0].Operations = slices.Delete(r.Spec.Transitions[0].Operations, 3, 4)
			case "unbacked-mutation":
				r.Spec.Operations[3].DependsOn = []string{"quiesce"}
			case "independent-mutation":
				r.Spec.Operations[3].DependsOn = []string{"images"}
				r.Spec.Operations[4].DependsOn = []string{"backup"}
			case "second-writer":
				r.Spec.Operations[3].Type = "helm"
				r.Spec.Operations[3].Command = nil
				r.Spec.Operations[3].Script = nil
			case "second-source":
				r.Spec.Operations = append(r.Spec.Operations, spec.Operation{ID: "another-source", Type: "gitops", DependsOn: []string{"sync"}})
				r.Spec.Transitions[0].Operations = append(r.Spec.Transitions[0].Operations, "another-source")
			case "early-fixture":
				r.Spec.Assets = append(r.Spec.Assets, spec.Asset{ID: "fixture", Type: "file-tree", Source: "fixture"})
				r.Spec.Checks[0].Fixtures = []string{"fixture"}
				r.Spec.Operations = append(r.Spec.Operations, spec.Operation{ID: "fixtures", Type: "seed", Asset: "fixture", PVC: "test-fixtures", MountPath: "/fixtures", StorageBytes: 1024, DependsOn: []string{"images"}})
				r.Spec.Transitions[0].Operations = append(r.Spec.Transitions[0].Operations, "fixtures")
				r.Spec.Operations[2].DependsOn = append(r.Spec.Operations[2].DependsOn, "fixtures")
			case "missing-quiesce":
				r.Spec.Deployment.GitOps.Data.Quiesce = ""
			case "cycle":
				r.Spec.Operations[1].DependsOn = []string{"sync"}
			}
			if err := spec.ValidateRelease(r); err != nil && change != "cycle" && change != "ambiguous" && change != "missing-quiesce" {
				t.Fatal("invalid control release", err)
			}
			cut, err := gitOpsDataSelection(r, from)
			if change != "none" && change != "initial" {
				if err == nil {
					t.Fatal("unsupported procedure cut passed", change)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			ids := func(ops []spec.Operation) []string {
				out := []string{}
				for _, o := range ops {
					out = append(out, o.ID)
				}
				return out
			}
			want := []string{"quiesce", "backup", "migration"}
			if change == "initial" {
				want = []string{}
			}
			if !reflect.DeepEqual(ids(cut.before), want) || !reflect.DeepEqual(ids(cut.after), []string{"writes"}) || cut.source != "sync" {
				t.Fatalf("signed dependency order changed: %+v", cut)
			}
		})
	}
}
