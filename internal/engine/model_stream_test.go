package engine

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
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

func TestNativeSeedStreamsVerifiedFilesAndRetriesOnlyAfterQuiescence(t *testing.T) {
	ctx := context.Background()
	e, client, policy := fixture(t)
	plan, verified := fixturePlan(t, e, policy)
	content := []byte("model shard bytes")
	files := []spec.FileRecord{{Path: "first.bin", Digest: spec.Hash(content), Size: int64(len(content))}, {Path: "second.bin", Digest: spec.Hash(content), Size: int64(len(content))}}
	cache := t.TempDir()
	blob, err := bundle.BlobPath(cache, files[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(blob), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(blob, content, 0600); err != nil {
		t.Fatal(err)
	}
	verified.Root = cache
	helper := "sha256:" + strings.Repeat("d", 64)
	verified.Index.Lock.Assets = []spec.LockedAsset{{ID: "model", Type: "model-tree", Digest: spec.Hash([]byte("model-tree")), Files: files}, {ID: "helper", Type: "image", Digest: helper}}
	verified.Index.Lock.Assets = append(verified.Index.Lock.Assets, spec.LockedAsset{ID: "runner", Type: "image", Digest: "sha256:" + strings.Repeat("c", 64)})
	e.Site.Spec.HelperImage = helper
	op := spec.Operation{ID: "seed-model", Type: "seed", Asset: "model", PVC: "model-v2", MountPath: "/models", ModelSubPath: "artifact", StorageBytes: 1024, TimeoutSeconds: 5}
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "seed")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "seed")
	policy.Spec.Epoch++
	admitFixturePolicy(t, e, policy)
	verified.Index.Lock.Release.Spec.Operations = []spec.Operation{op}
	verified.Index.Lock.Release.Spec.Transitions[0].Operations = []string{op.ID}
	plan.Operations = []spec.Operation{op}
	plan.PolicyEpoch = policy.Spec.Epoch
	plan.PolicyDigest = mustDigest(t, policy)
	plan.SiteDigest = mustDigest(t, e.Site)
	updatedSite, _ := spec.Canonical(e.Site)
	if err = os.WriteFile(plan.SitePath, updatedSite, 0600); err != nil {
		t.Fatal(err)
	}
	plan.SourceSiteDigest, err = sourceSiteDigest(plan.SitePath)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := spec.Canonical(plan)
	site, _ := spec.Canonical(e.Site)
	if err = e.Store.CreateRun(ctx, state.Run{ID: "native-run", Application: "app", TargetID: plan.Snapshot.TargetID, Namespace: "test", PlanDigest: mustDigest(t, plan), Plan: body, Site: site}); err != nil {
		t.Fatal(err)
	}
	intent, err := e.Store.Intent(ctx, "native-run", op.ID, op, "")
	if err != nil {
		t.Fatal(err)
	}
	jobs := []string{}
	client.PrependReactor("create", "jobs", func(a ktesting.Action) (bool, runtime.Object, error) {
		job := a.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		job.UID = types.UID("uid-" + job.Name)
		jobs = append(jobs, job.Name)
		if job.Spec.Template.Spec.Containers[0].Stdin {
			yes := true
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: job.Name + "-pod", Namespace: "test", UID: types.UID("pod-" + job.Name), Labels: job.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "operation", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
			if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("pods"), pod, "test"); err != nil {
				t.Fatal(err)
			}
		} else {
			if len(job.Spec.Template.Spec.Containers[0].Command) > 2 && job.Spec.Template.Spec.Containers[0].Command[2] == "verify-model" && !job.Spec.Template.Spec.Containers[0].VolumeMounts[1].ReadOnly {
				t.Fatal("independent verifier has writable model")
			}
			job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		}
		return false, nil, nil
	})
	root := t.TempDir()
	attachCount := 0
	e.ModelAttach = func(ctx context.Context, podName string, stdin io.Reader, stdout, stderr io.Writer) error {
		attachCount++
		current, err := e.Store.LatestOperation(ctx, "native-run", op.ID)
		if err != nil {
			return err
		}
		worker, err := e.operationWorker(ctx, "native-run", op.ID, current.Attempt, op.ID)
		if err != nil {
			return err
		}
		receiver, err := e.Store.ModelReceiver(ctx, worker)
		if err != nil || receiver.PodName != podName {
			t.Fatal("model bytes sent before durable receiver binding", err)
		}
		reader := stdin
		if attachCount == 1 {
			reader = io.LimitReader(stdin, 1538)
		}
		err = modelstage.Receive(ctx, root, "artifact", files, reader)
		pod, getErr := client.CoreV1().Pods("test").Get(ctx, podName, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		job, getErr := client.BatchV1().Jobs("test").Get(ctx, worker.Name, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		pod.Status.Phase = corev1.PodSucceeded
		condition := batchv1.JobComplete
		exit := int32(0)
		if err != nil {
			pod.Status.Phase = corev1.PodFailed
			condition = batchv1.JobFailed
			exit = 1
		}
		pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: exit}}
		job.Status.Conditions = []batchv1.JobCondition{{Type: condition, Status: corev1.ConditionTrue}}
		if _, getErr = client.CoreV1().Pods("test").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); getErr != nil {
			return getErr
		}
		if _, getErr = client.BatchV1().Jobs("test").UpdateStatus(ctx, job, metav1.UpdateOptions{}); getErr != nil {
			return getErr
		}
		return err
	}
	if _, err = e.seedPVC(ctx, "native-run", op, verified); spec.ExitCode(err) != 13 {
		t.Fatalf("lost stream accepted: %v", err)
	}
	if err = e.Store.Complete(ctx, intent, "uncertain", nil); err != nil {
		t.Fatal(err)
	}
	if err = e.clusterRecord(ctx, "native-run", mustDigest(t, plan), "uncertain", intent); err != nil {
		t.Fatal(err)
	}
	prior := newResult(plan, "native-run", mustDigest(t, plan))
	prior.State, prior.Error, prior.FinishedAt = "needs_reconciliation", "previous attachment ended before confirmation", spec.Now()
	if err = e.Store.SetState(ctx, "native-run", prior.State, true, prior); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "artifact/first.bin")
	when := time.Unix(1500000000, 0)
	if err = os.Chtimes(first, when, when); err != nil {
		t.Fatal("complete first shard was not retained", err)
	}
	worker, err := e.operationWorker(ctx, "native-run", op.ID, intent.Attempt, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Store.ModelReceiver(ctx, worker)
	if err != nil {
		t.Fatal(err)
	}
	pod, _ := client.CoreV1().Pods("test").Get(ctx, r.PodName, metav1.GetOptions{})
	terminated := pod.Status.DeepCopy()
	pod.Status.Phase = corev1.PodRunning
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
	if _, err = client.CoreV1().Pods("test").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = e.nativeAttemptStatus(ctx, intent); spec.ExitCode(err) != 13 {
		t.Fatalf("terminal Job allowed retry while original Pod running: %v", err)
	}
	if _, err = e.Resume(ctx, "native-run", verified, policy, nil, true); spec.ExitCode(err) != 13 {
		t.Fatalf("Resume raced original Pod: %v", err)
	}
	if err = e.recoveryQuiescent(ctx, "native-run"); spec.ExitCode(err) != 13 {
		t.Fatalf("recovery raced original receiver: %v", err)
	}
	pod.Status = *terminated
	if _, err = client.CoreV1().Pods("test").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if status, err := e.nativeAttemptStatus(ctx, intent); err != nil || status != "failed" {
		t.Fatalf("terminated partial not reconciled: %s %v", status, err)
	}
	result, err := e.Resume(ctx, "native-run", verified, policy, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "succeeded" || result.Error != "" {
		t.Fatalf("resumed release not accepted: %#v", result)
	}
	events, err := e.Store.Events(ctx, "native-run")
	if err != nil {
		t.Fatal(err)
	}
	retained := false
	for _, event := range events {
		if event.Type != "run_resumed" {
			continue
		}
		var body struct {
			PreviousOutcome spec.RunResult `json:"previousOutcome"`
		}
		if err := spec.Decode(event.Data, &body); err != nil {
			t.Fatal(err)
		}
		retained = body.PreviousOutcome.Error == prior.Error && body.PreviousOutcome.FinishedAt == prior.FinishedAt && body.PreviousOutcome.State == prior.State
	}
	if !retained {
		t.Fatal("resuming erased the previous failed outcome")
	}
	if len(jobs) != 4 || jobs[0] == jobs[1] || attachCount != 2 {
		t.Fatalf("retry did not use fresh receiver and separate verifier: %v attaches=%d", jobs, attachCount)
	}
	info, err := os.Stat(first)
	if err != nil || !info.ModTime().Equal(when) {
		t.Fatal("retry rewrote verified shard", err)
	}
	if err = modelstage.Verify(filepath.Join(root, "artifact"), files); err != nil {
		t.Fatal(err)
	}
	pod.UID = "replacement"
	if _, err = client.CoreV1().Pods("test").Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = e.modelReceiverStatus(ctx, worker); spec.ExitCode(err) != 13 {
		t.Fatalf("same-name receiver replacement trusted: %v", err)
	}
}

func TestResumeRejectsStoredPlanMetadataTamperBeforeClusterAccess(t *testing.T) {
	e, client, policy, p, v, _ := workerFixture(t)
	p.Metadata.Name = "edited after admission"
	body, err := spec.Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(e.StateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`UPDATE runs SET plan_json=? WHERE id='worker-run'`, body); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()
	if _, err = e.Resume(context.Background(), "worker-run", v, policy, nil, true); spec.ExitCode(err) != 13 || !strings.Contains(err.Error(), "stored plan") {
		t.Fatalf("stored metadata tamper admitted: %v", err)
	}
	if len(client.Actions()) != 0 {
		t.Fatal("tampered plan contacted cluster before integrity rejection")
	}
}

func TestNativeModelPodRecipeRejectsAdmissionMutations(t *testing.T) {
	e, client, _, p, _, intent := workerFixture(t)
	completeWorkers(client)
	if _, err := e.executeJob(context.Background(), "worker-run", p.Operations[0].ID, "internal/helper", []string{"/fixed"}, nil, nil, "", "", 1); err != nil {
		t.Fatal(err)
	}
	w, err := e.Store.Worker(context.Background(), "worker-run", intent.StepID, intent.Attempt, intent.StepID)
	if err != nil {
		t.Fatal(err)
	}
	job, err := client.BatchV1().Jobs("test").Get(context.Background(), w.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	seconds := int64(300)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", UID: "pod-uid", Labels: job.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy()}
	pod.Spec.NodeName = "scheduled-node"
	pod.Spec.Tolerations = []corev1.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &seconds}}
	if _, err = modelPodRecipe(job, pod, w); err != nil {
		t.Fatalf("ordinary scheduling defaults rejected: %v", err)
	}
	for _, mutation := range []string{"owner", "image", "command", "privileged", "extra-container"} {
		t.Run(mutation, func(t *testing.T) {
			changed := pod.DeepCopy()
			switch mutation {
			case "owner":
				changed.OwnerReferences[0].UID = "another-job"
			case "image":
				changed.Spec.Containers[0].Image = "attacker"
			case "command":
				changed.Spec.Containers[0].Command = []string{"/other"}
			case "privileged":
				changed.Spec.Containers[0].SecurityContext.Privileged = &yes
			case "extra-container":
				changed.Spec.Containers = append(changed.Spec.Containers, corev1.Container{Name: "sidecar", Image: "other"})
			}
			if _, err := modelPodRecipe(job, changed, w); spec.ExitCode(err) != 13 {
				t.Fatalf("mutated receiver admitted: %v", err)
			}
		})
	}
}

func TestNativeUnsupportedRecipesFailBeforeVolumeMutation(t *testing.T) {
	for _, mutation := range []string{"floating-helper", "carrier-image", "authored-args", "secret", "helper-mount", "manifest-mount", "dirty-mount"} {
		t.Run(mutation, func(t *testing.T) {
			e, client, policy := fixture(t)
			_, v := fixturePlan(t, e, policy)
			digest := "sha256:" + strings.Repeat("d", 64)
			e.Site.Spec.HelperImage = digest
			v.Index.Lock.Assets = []spec.LockedAsset{{ID: "helper", Type: "image", Digest: digest}, {ID: "model", Type: "model-tree", Digest: spec.Hash([]byte("asset")), Files: []spec.FileRecord{{Path: "weights", Digest: spec.Hash([]byte("x")), Size: 1}}}}
			op := spec.Operation{ID: "seed", Type: "seed", Asset: "model", PVC: "model-v2", StorageBytes: 1024, MountPath: "/models"}
			switch mutation {
			case "floating-helper":
				e.Site.Spec.HelperImage = "helper"
			case "carrier-image":
				op.Image = "helper"
			case "authored-args":
				op.Args = []string{"ignored"}
			case "secret":
				op.SecretRefs = []string{"license"}
			case "helper-mount":
				op.MountPath = "/usr/local/bin/cinderlock"
			case "manifest-mount":
				op.MountPath = "/cinderlock-manifest/nested"
			case "dirty-mount":
				op.MountPath = "/models/../tmp"
			}
			client.ClearActions()
			if _, err := e.seedPVC(context.Background(), "native-run", op, v); err == nil {
				t.Fatal("unsupported native recipe accepted")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" && action.GetVerb() != "list" {
					t.Fatalf("invalid native recipe mutated %s", action.GetResource().Resource)
				}
			}
		})
	}
}
