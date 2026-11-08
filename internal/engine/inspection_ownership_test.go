package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestInspectionRejectsLostOrCompetingOwnership(t *testing.T) {
	for _, change := range []struct {
		name   string
		mutate func(*metav1.ObjectMeta)
	}{
		{"release-name", func(m *metav1.ObjectMeta) { delete(m.Annotations, "meta.helm.sh/release-name") }},
		{"release-namespace", func(m *metav1.ObjectMeta) { delete(m.Annotations, "meta.helm.sh/release-namespace") }},
		{"managed-by", func(m *metav1.ObjectMeta) { delete(m.Labels, "app.kubernetes.io/managed-by") }},
		{"other-manager", func(m *metav1.ObjectMeta) { m.Labels["app.kubernetes.io/managed-by"] = "other" }},
		{"argo-annotation", func(m *metav1.ObjectMeta) {
			m.Annotations["argocd.argoproj.io/tracking-id"] = "application:apps/Deployment:test/app"
		}},
		{"flux-annotation", func(m *metav1.ObjectMeta) { m.Annotations["kustomize.toolkit.fluxcd.io/name"] = "owner" }},
		{"unknown-controller", func(m *metav1.ObjectMeta) {
			yes := true
			m.OwnerReferences = []metav1.OwnerReference{{APIVersion: "operator.invalid/v1", Kind: "Application", Name: "owner", UID: "owner-uid", Controller: &yes}}
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			e, client, _ := fixture(t)
			ctx := context.Background()
			deployment, err := client.AppsV1().Deployments("test").Get(ctx, "app", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			deployment.Labels["app.kubernetes.io/managed-by"] = "Helm"
			deployment.Annotations["meta.helm.sh/release-namespace"] = "test"
			if _, err = client.AppsV1().Deployments("test").Update(ctx, deployment, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err = e.Inspect(ctx); err != nil {
				t.Fatalf("qualified baseline rejected: %v", err)
			}
			change.mutate(&deployment.ObjectMeta)
			if _, err = client.AppsV1().Deployments("test").Update(ctx, deployment, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err = e.Inspect(ctx); spec.ExitCode(err) != 16 {
				t.Fatalf("ownership change accepted: %v", err)
			}
		})
	}
}

func TestInspectionBindsNoncontrollerOwnerReferences(t *testing.T) {
	e, client, _ := fixture(t)
	ctx := context.Background()
	before, err := e.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := client.AppsV1().Deployments("test").Get(ctx, "app", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deployment.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "retention-anchor", UID: "anchor-uid"}, {APIVersion: "v1", Kind: "ConfigMap", Name: "other-anchor", UID: "other-uid"}}
	if _, err = client.AppsV1().Deployments("test").Update(ctx, deployment, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	after, err := e.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, err := snapshotDigest(before)
	if err != nil {
		t.Fatal(err)
	}
	b, err := snapshotDigest(after)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("ownership graph change did not invalidate the plan")
	}
	deployment.OwnerReferences[0], deployment.OwnerReferences[1] = deployment.OwnerReferences[1], deployment.OwnerReferences[0]
	if _, err = client.AppsV1().Deployments("test").Update(ctx, deployment, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	reordered, err := e.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := snapshotDigest(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if c != b {
		t.Fatal("owner-reference ordering changed the ownership binding")
	}
}

func TestInspectionRecognizesQualifiedStatefulSetVolumeOwner(t *testing.T) {
	e, client, _ := fixture(t)
	ctx := context.Background()
	set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "database", Namespace: "test", UID: "database-uid", Labels: map[string]string{"app.kubernetes.io/instance": "app", "app.kubernetes.io/managed-by": "Helm"}, Annotations: map[string]string{"meta.helm.sh/release-name": "app", "meta.helm.sh/release-namespace": "test"}}}
	if _, err := client.AppsV1().StatefulSets("test").Create(ctx, set, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "data-database-0", Namespace: "test", UID: "claim-uid", Labels: map[string]string{"app.kubernetes.io/instance": "app"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(set, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "StatefulSet"})}}}
	if _, err := client.CoreV1().PersistentVolumeClaims("test").Create(ctx, claim, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	before, err := e.Inspect(ctx)
	if err != nil {
		t.Fatalf("qualified parent graph rejected: %v", err)
	}
	if fact := inspectionFact(t, before, "ownership/PersistentVolumeClaim/"+claim.Name); fact.Value != "statefulset" || !strings.Contains(fact.Source, string(set.UID)) {
		t.Fatalf("parent qualification missing: %+v", fact)
	}
	claim.OwnerReferences[0].UID = "replaced-parent"
	if _, err := client.CoreV1().PersistentVolumeClaims("test").Update(ctx, claim, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	after, err := e.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fact := inspectionFact(t, after, "ownership/PersistentVolumeClaim/"+claim.Name); fact.Value != "read_retain" {
		t.Fatalf("replacement parent was qualified: %+v", fact)
	}
	a, err := snapshotDigest(before)
	if err != nil {
		t.Fatal(err)
	}
	b, err := snapshotDigest(after)
	if err != nil || a == b {
		t.Fatalf("replacement parent did not stale approved state: %v", err)
	}
}

func TestRetirementCanInventoryDefaultRetainedStatefulSetClaim(t *testing.T) {
	e, client, policy := fixture(t)
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "uninstall")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "uninstall")
	policy.Spec.Epoch++
	admitFixturePolicy(t, e, policy)
	p, v := fixturePlan(t, e, policy)
	ctx := context.Background()
	set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "database", Namespace: "test", UID: "database-uid", Labels: map[string]string{"app.kubernetes.io/instance": "app", "app.kubernetes.io/managed-by": "Helm"}, Annotations: map[string]string{"meta.helm.sh/release-name": "app", "meta.helm.sh/release-namespace": "test"}}, Spec: appsv1.StatefulSetSpec{VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data"}}}}}
	if _, err := client.AppsV1().StatefulSets("test").Create(ctx, set, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "data-database-0", Namespace: "test", UID: "retained-claim", Labels: map[string]string{"app.kubernetes.io/instance": "app"}}}
	if _, err := client.CoreV1().PersistentVolumeClaims("test").Create(ctx, claim, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	base := e.HelmRunner
	uninstalled := false
	e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "get" && args[1] == "manifest" {
			return []byte("apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: database\n"), nil
		}
		if args[0] == "uninstall" {
			uninstalled = true
			return nil, nil
		}
		return base(ctx, args...)
	}
	retirement, err := e.UninstallPlan(ctx, v, p.BundlePath, p.SitePath, policy)
	if err != nil {
		t.Fatalf("read/retain claim was rejected as a root requiring mutation ownership: %v", err)
	}
	if !retirement.Executable || len(retirement.RetainedResources) != 1 || retirement.RetainedResources[0].UID != "retained-claim" {
		t.Fatalf("retained identity not planned: %+v", retirement)
	}
	if err := e.uninstall(ctx, retirement); err != nil || !uninstalled {
		t.Fatalf("read/retain retirement blocked: %v", err)
	}
}

func TestPermissionPlanCannotMutateReadRetainClaim(t *testing.T) {
	for _, scope := range []string{"helm", "unowned", "unknown-controller"} {
		t.Run(scope, func(t *testing.T) {
			e, client, _ := fixture(t)
			ctx := context.Background()
			claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "test", UID: "claim-uid", Labels: map[string]string{"app.kubernetes.io/instance": "app", "app.kubernetes.io/managed-by": "Helm"}, Annotations: map[string]string{"meta.helm.sh/release-name": "app", "meta.helm.sh/release-namespace": "test"}}}
			if scope == "unowned" {
				delete(claim.Labels, "app.kubernetes.io/managed-by")
				claim.Annotations = nil
			}
			if scope == "unknown-controller" {
				yes := true
				claim.OwnerReferences = []metav1.OwnerReference{{APIVersion: "operator.invalid/v1", Kind: "Application", Name: "owner", UID: "owner-uid", Controller: &yes}}
			}
			if _, err := client.CoreV1().PersistentVolumeClaims("test").Create(ctx, claim, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			snapshot, err := e.Inspect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			p := spec.Plan{Snapshot: snapshot, Executable: true, Operations: []spec.Operation{{ID: "deploy", Type: "helm"}}}
			objects := []map[string]any{{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": map[string]any{"name": "data"}}}
			e.addPermissionFindings(ctx, &p, objects)
			if p.Executable != (scope == "helm") {
				t.Fatalf("wrong direct-mutation ownership gate: scope=%s executable=%v", scope, p.Executable)
			}
			if scope != "helm" {
				found := false
				for _, finding := range p.Findings {
					found = found || finding.Code == "PVC_OWNERSHIP_UNQUALIFIED" && finding.Severity == "blocker" && finding.Source == "operation/deploy"
				}
				if !found {
					t.Fatal("unqualified PVC mutation was not disclosed")
				}
			}
		})
	}
}
