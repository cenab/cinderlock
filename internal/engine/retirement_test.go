package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const keptPVCManifest = `apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: models
  annotations:
    helm.sh/resource-policy: keep
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: internal/image
`

func TestRetirementRetainsReviewedUIDAndSkipsHooks(t *testing.T) {
	e, client, policy := fixture(t)
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "uninstall")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "uninstall")
	policy.Spec.Epoch++
	admitFixturePolicy(t, e, policy)
	p, verified := fixturePlan(t, e, policy)
	ctx := context.Background()
	if _, err := client.CoreV1().PersistentVolumeClaims("test").Create(ctx, &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "models", Namespace: "test", UID: types.UID("pvc-original")}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	base := e.HelmRunner
	uninstalled := false
	e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "get" && args[1] == "manifest" {
			return []byte(keptPVCManifest), nil
		}
		if args[0] == "uninstall" {
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "--keep-history --no-hooks --cascade foreground --wait") {
				t.Fatalf("unsafe Helm retirement flags: %v", args)
			}
			uninstalled = true
			return nil, nil
		}
		return base(ctx, args...)
	}
	retirement, err := e.UninstallPlan(ctx, verified, p.BundlePath, p.SitePath, policy)
	if err != nil {
		t.Fatal(err)
	}
	if retirement.Kind != "RetirementPlan" || len(retirement.RetainedResources) != 1 || retirement.RetainedResources[0].UID != "pvc-original" {
		t.Fatalf("retirement does not bind retained data: %#v", retirement)
	}
	if err := e.verifyRecipeBinding(retirement, verified); err != nil {
		t.Fatal(err)
	}
	if err := e.uninstall(ctx, retirement); err != nil || !uninstalled {
		t.Fatalf("reviewed uninstall failed: %v", err)
	}
	claim, _ := client.CoreV1().PersistentVolumeClaims("test").Get(ctx, "models", metav1.GetOptions{})
	claim.UID = "replaced-pvc"
	if _, err := client.CoreV1().PersistentVolumeClaims("test").Update(ctx, claim, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	uninstalled = false
	if err := e.uninstall(ctx, retirement); err == nil || uninstalled {
		t.Fatal("retirement mutated after retained volume identity changed")
	}
}

func TestRetirementBlocksDataDeletionAndWorkloadRetention(t *testing.T) {
	for _, scenario := range []string{"missing-keep", "garbage-collection", "kept-workload", "lifecycle", "stateful-delete"} {
		t.Run(scenario, func(t *testing.T) {
			e, client, _ := fixture(t)
			manifest := keptPVCManifest
			claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "models", Namespace: "test", UID: "pvc-original"}}
			switch scenario {
			case "missing-keep":
				manifest = strings.Replace(manifest, "helm.sh/resource-policy: keep", "other: annotation", 1)
			case "garbage-collection":
				claim.OwnerReferences = []metav1.OwnerReference{{Kind: "Deployment", Name: "app", UID: "deployment-uid"}}
			case "kept-workload":
				manifest = strings.Replace(manifest, "  name: app\nspec:", "  name: app\n  annotations:\n    helm.sh/resource-policy: keep\nspec:", 1)
			case "lifecycle":
				manifest += "          lifecycle:\n            preStop:\n              exec:\n                command: [delete-data]\n"
			case "stateful-delete":
				manifest = "apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: db\n"
				set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "test"}, Spec: appsv1.StatefulSetSpec{PersistentVolumeClaimRetentionPolicy: &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{WhenDeleted: appsv1.DeletePersistentVolumeClaimRetentionPolicyType}}}
				if _, err := client.AppsV1().StatefulSets("test").Create(context.Background(), set, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := client.CoreV1().PersistentVolumeClaims("test").Create(context.Background(), claim, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			e.HelmRunner = func(_ context.Context, args ...string) ([]byte, error) {
				if args[0] != "get" || args[1] != "manifest" {
					return nil, errors.New("unexpected mutation")
				}
				return []byte(manifest), nil
			}
			client.ClearActions()
			if _, err := e.uninstallInventory(context.Background()); err == nil {
				t.Fatal("unsafe data retirement accepted")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" && action.GetVerb() != "list" {
					t.Fatal("retirement inventory mutated the cluster")
				}
			}
		})
	}
}

func TestOnlyRecoveryCanSupersedeExistingRun(t *testing.T) {
	e, _, policy := fixture(t)
	p, verified := fixturePlan(t, e, policy)
	p.SourceRun = "unresolved-migration"
	if err := e.verifyRecipeBinding(p, verified); err == nil {
		t.Fatal("ordinary plan may supersede an unresolved run")
	}
}
