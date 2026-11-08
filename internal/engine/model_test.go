package engine

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/modelstage"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
)

func TestModelVerifierChecksBytesSizesAndClosedTree(t *testing.T) {
	content := []byte("locked model bytes")
	record := spec.FileRecord{Path: "model/weights $'one'.bin", Digest: spec.Hash(content), Size: int64(len(content))}
	makeTree := func(t *testing.T) string {
		t.Helper()
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, "model"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, record.Path), content, 0600); err != nil {
			t.Fatal(err)
		}
		return root
	}
	if err := modelstage.Verify(makeTree(t), []spec.FileRecord{record}); err != nil {
		t.Fatalf("valid tree rejected: %v", err)
	}
	for _, mutation := range []string{"same-size-corruption", "wrong-size", "missing", "extra-file", "extra-directory", "symlink"} {
		t.Run(mutation, func(t *testing.T) {
			root := makeTree(t)
			name := filepath.Join(root, record.Path)
			var err error
			switch mutation {
			case "same-size-corruption":
				err = os.WriteFile(name, []byte(strings.Repeat("x", len(content))), 0600)
			case "wrong-size":
				err = os.WriteFile(name, []byte("short"), 0600)
			case "missing":
				err = os.Remove(name)
			case "extra-file":
				err = os.WriteFile(filepath.Join(root, "extra.bin"), []byte("unlisted"), 0600)
			case "extra-directory":
				err = os.Mkdir(filepath.Join(root, "unlisted"), 0700)
			case "symlink":
				if err = os.Remove(name); err == nil {
					err = os.Symlink(filepath.Join(t.TempDir(), "outside"), name)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := modelstage.Verify(root, []spec.FileRecord{record}); err == nil {
				t.Fatal("unverified model tree accepted")
			}
		})
	}
	for _, records := range [][]spec.FileRecord{nil, {record, record}, {{Path: "../escape", Digest: record.Digest, Size: record.Size}}, {{Path: "/absolute", Digest: record.Digest, Size: record.Size}}, {{Path: "model", Digest: "sha256:not-a-hash", Size: 1}}} {
		if _, err := modelstage.Manifest(records); err == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
}

func TestSeedSuccessRequiresSeparateReadOnlySignedManifestJob(t *testing.T) {
	e, client, policy := fixture(t)
	plan, verified := fixturePlan(t, e, policy)
	digest := "sha256:" + strings.Repeat("c", 64)
	files := []spec.FileRecord{{Path: "weights.bin", Digest: spec.Hash([]byte("x")), Size: 1}}
	verified.Index.Lock.Assets = []spec.LockedAsset{{ID: "model", Type: "model", Digest: digest, Files: files}, {ID: "runner", Type: "image", Digest: digest}, {ID: "helper", Type: "image", Digest: digest}}
	e.Site.Spec.HelperImage = "helper"
	e.Site.Spec.Registry = "registry.invalid/release"
	jobs := []*batchv1.Job{}
	client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		job.UID = types.UID("uid-" + job.Name)
		jobs = append(jobs, job.DeepCopy())
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		return false, nil, nil
	})
	operation := spec.Operation{ID: "seed-model", Type: "seed", Asset: "model", Image: "runner", Command: []string{"/vendor-copy"}, PVC: "model-v2", MountPath: "/models", ModelSubPath: "artifact", StorageBytes: 1024, Idempotent: true, Script: fixtureScript("inference"), TimeoutSeconds: 1}
	operation.Script.Resources = &spec.WorkerResources{CPUMillis: 250, MemoryBytes: 128 << 20, EphemeralStorageBytes: 32 << 20, TemporaryBytes: 4 << 20}
	planBody, _ := spec.Canonical(plan)
	siteBody, _ := spec.Canonical(e.Site)
	if err := e.Store.CreateRun(context.Background(), state.Run{ID: "run-model", Application: "app", TargetID: plan.Snapshot.TargetID, Namespace: "test", PlanDigest: "model-plan", Plan: planBody, Site: siteBody}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Store.Intent(context.Background(), "run-model", operation.ID, operation, jobName("run-model", operation.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.seedPVC(context.Background(), "run-model", operation, verified); err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("seed completion skipped fixed verifier: %d Jobs", len(jobs))
	}
	assertJobBudget(t, jobs[0], operation.Script.Resources, operation.TimeoutSeconds)
	assertJobBudget(t, jobs[1], nil, operation.TimeoutSeconds)
	verifier := jobs[1].Spec.Template.Spec
	container := verifier.Containers[0]
	if !slices.Equal(container.Command, []string{"/usr/local/bin/cinderlock", "helper", "verify-model"}) || !strings.Contains(container.Image, "/helper@sha256:") {
		t.Fatalf("verifier does not use locked helper and fixed entrypoint: %#v", container)
	}
	if !slices.Contains(container.Args, "/cinderlock-model") || !slices.Contains(container.Args, "--subpath") || !slices.Contains(container.Args, "artifact") {
		t.Fatal("verifier ignored explicit confined model subdirectory")
	}
	for _, mount := range container.VolumeMounts {
		if (mount.Name == "manifest" || mount.Name == "model") && !mount.ReadOnly {
			t.Fatalf("verifier volume is writable: %#v", mount)
		}
	}
	for _, volume := range verifier.Volumes {
		if volume.PersistentVolumeClaim != nil && !volume.PersistentVolumeClaim.ReadOnly {
			t.Fatal("verifier PVC source is writable")
		}
	}
	manifest, err := client.CoreV1().ConfigMaps("test").Get(context.Background(), jobName("run-model", "manifest-seed-model"), metav1.GetOptions{})
	if err != nil || manifest.Immutable == nil || !*manifest.Immutable {
		t.Fatalf("signed manifest is not immutable: %#v %v", manifest, err)
	}
	expected, _ := modelstage.Manifest(files)
	if manifest.Data["files.json"] != string(expected) {
		t.Fatal("verifier did not receive the signed file list")
	}
	manifest.Data["files.json"] = "[]"
	if _, err := client.CoreV1().ConfigMaps("test").Update(context.Background(), manifest, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.verifySeed(context.Background(), "run-model", operation, verified); err == nil {
		t.Fatal("changed manifest trusted on resume")
	}
}

func TestMissingModelVerifierBlocksBeforeVolumeCreation(t *testing.T) {
	e, client, policy := fixture(t)
	_, verified := fixturePlan(t, e, policy)
	verified.Index.Lock.Assets = []spec.LockedAsset{{ID: "model", Digest: spec.Hash([]byte("x")), Files: []spec.FileRecord{{Path: "model", Digest: spec.Hash([]byte("x")), Size: 1}}}}
	client.ClearActions()
	if _, err := e.seedPVC(context.Background(), "run", spec.Operation{Asset: "model", PVC: "model", StorageBytes: 1}, verified); err == nil {
		t.Fatal("seed accepted missing verifier")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" && action.GetVerb() != "list" {
			t.Fatalf("missing verifier discovered only after mutation: %s", action.GetVerb())
		}
	}
}
