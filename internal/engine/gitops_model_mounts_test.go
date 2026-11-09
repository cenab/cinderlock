package engine

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestGitOpsRootModelMountNeedsExplicitContainerReadOnly(t *testing.T) {
	pod := corev1.PodSpec{Containers: []corev1.Container{{Name: "application", VolumeMounts: []corev1.VolumeMount{{Name: "models", MountPath: "/models", ReadOnly: true}}}}, Volumes: []corev1.Volume{{Name: "models", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "model-v1"}}}}}
	mounts, err := gitOpsClaimMounts(pod, "model-v1", "", true)
	if err != nil || len(mounts) != 1 || mounts[0].Mount.MountPath != "/models" || mounts[0].Mount.SubPath != "" || !mounts[0].Mount.ReadOnly {
		t.Fatalf("explicit root read-only mount rejected because source bit is omitted: %v %#v", err, mounts)
	}
	pod.Containers[0].VolumeMounts[0].ReadOnly = false
	if _, err := gitOpsClaimMounts(pod, "model-v1", "", true); err == nil {
		t.Fatal("writable model mount accepted")
	}
}

func TestGitOpsNativeChartRootModelMount(t *testing.T) {
	chart := filepath.Join("..", "..", "examples", "document-qa", "chart")
	values, err := os.ReadFile(filepath.Join(chart, "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := yaml.Unmarshal(values, &input); err != nil {
		t.Fatal(err)
	}
	input["models"].(map[string]any)["existingClaim"] = "model-v1"
	body, err := os.ReadFile(filepath.Join(chart, "templates", "deployment.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// This unchanged template uses only these two Helm functions and Go's printf.
	// This is a mapping regression, not Helm/controller qualification.
	renderer, err := template.New("native-deployment").Funcs(template.FuncMap{"quote": func(value any) string { return strconv.Quote(fmt.Sprint(value)) }, "default": func(fallback, value string) string {
		if value == "" {
			return fallback
		}
		return value
	}}).Parse(string(body))
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := renderer.Execute(&rendered, map[string]any{"Values": input, "Release": map[string]string{"Name": "document-qa", "Service": "Helm"}}); err != nil {
		t.Fatal(err)
	}
	var deployment appsv1.Deployment
	objects, err := PermissionObjects(rendered.Bytes())
	if err != nil || len(objects) != 1 {
		t.Fatal("native Deployment render unavailable", err)
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(objects[0], &deployment); err != nil {
		t.Fatal(err)
	}
	mounts, err := gitOpsClaimMounts(deployment.Spec.Template.Spec, "model-v1", "", true)
	if err != nil || len(mounts) != 1 || !mounts[0].Mount.ReadOnly || mounts[0].Mount.MountPath != "/models" || mounts[0].Mount.SubPath != "" {
		t.Fatalf("unchanged native chart model root mapping rejected: %v %#v", err, mounts)
	}
}

func TestGitOpsPreparedVolumeRejectsPendingUnrecordedWriter(t *testing.T) {
	e, client, preparation, v, _, ref := completedPreparation(t)
	p := preparationChecks(t, e, preparation, ref)
	preparedDeployment(t, client, p)
	if _, err := e.gitOpsPreparedVolume(context.Background(), p, v, "fixtures-v2"); err != nil {
		t.Fatal("baseline prepared read-only consumer unavailable", err)
	}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "pending-writer", Namespace: "test", UID: "pending-writer-uid"}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "writer", VolumeMounts: []corev1.VolumeMount{{Name: "model", MountPath: "/models"}}}}, Volumes: []corev1.Volume{{Name: "model", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "fixtures-v2"}}}}}}}}
	if err := client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.gitOpsPreparedVolume(context.Background(), p, v, "fixtures-v2"); err == nil {
		t.Fatal("pending writable Job without a Pod was invisible to prepared-volume guards")
	}
}

func TestGitOpsActiveSeedGuardDoesNotInventCompletedReceipt(t *testing.T) {
	e, _, p, v, _, ref := completedPreparation(t)
	ctx := context.Background()
	if err := e.Store.SetState(ctx, ref.RunID, "mutating", true, nil); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(e.StateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// This is the real execute ordering: original workers have completed, but
	// advanceCheckpoint runs before Store.Complete records their seed outcome.
	if _, err := db.Exec("UPDATE operations SET state='intent',evidence_json=NULL WHERE run_id=? AND step_id=?", ref.RunID, p.Operations[0].ID); err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadGitOpsManifest(p.GitOps.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := e.gitOpsPreparationSeedFacts(ctx, p, v, manifest, p.Snapshot.TargetID)
	if err != nil || len(facts) != 1 || facts[0].Value != "false" {
		t.Fatalf("known in-flight original workers could not cross their checkpoint without claiming a receipt: %v %#v", err, facts)
	}
	if err := e.gitOpsPreparationComplete(ctx, p, v, ref.RunID); err == nil {
		t.Fatal("in-flight workers became a completed preparation receipt")
	}
}
