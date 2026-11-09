package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGitOpsFixtureExcludesReviewedAndPendingApplicationConsumers(t *testing.T) {
	for _, consumer := range []string{"none", "reviewed-deployment", "pending-job"} {
		t.Run(consumer, func(t *testing.T) {
			e, client, policy := fixture(t)
			p, v := fixturePlan(t, e, policy)
			p.Kind = "GitOpsChecksPlan"
			p.Operations = []spec.Operation{{ID: "seed-fixture", Type: "seed", Asset: "documents", PVC: "check-documents", MountPath: "/documents", StorageBytes: 1024}}
			p.Checks[0].Fixtures = []string{"documents"}
			v.Index.Lock.Assets = append(v.Index.Lock.Assets, spec.LockedAsset{ID: "documents", Type: "file-tree", Digest: spec.Hash([]byte("documents")), Files: []spec.FileRecord{{Path: "document.txt", Digest: spec.Hash([]byte("test")), Size: 4}}})
			manifest := []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: application}\nspec:\n  template:\n    spec:\n      containers: [{name: app, image: example.invalid/app}]\n")
			if consumer == "reviewed-deployment" {
				manifest = append(manifest, []byte("      volumes: [{name: documents, persistentVolumeClaim: {claimName: check-documents}}]\n")...)
			}
			path := filepath.Join(t.TempDir(), "reviewed.yaml")
			if err := os.WriteFile(path, manifest, 0600); err != nil {
				t.Fatal(err)
			}
			p.GitOps = &spec.GitOpsPlanBinding{ManifestPath: path}
			p.DesiredStateDigest = spec.Hash(manifest)
			if consumer == "pending-job" {
				job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "pending-writer", Namespace: "test", UID: "unknown-writer"}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "documents", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "check-documents"}}}}}}}}
				if err := client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job, "test"); err != nil {
					t.Fatal(err)
				}
			}
			findings := e.fixtureFindings(context.Background(), p, v)
			blocked := false
			for _, finding := range findings {
				blocked = blocked || finding.Severity == "blocker" && strings.Contains(finding.Code, "FIXTURE")
			}
			if blocked != (consumer != "none") {
				t.Fatalf("fixture consumer %s: blocked=%v findings=%#v", consumer, blocked, findings)
			}
		})
	}
}
