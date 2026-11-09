package engine

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/modelstage"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"
)

func (e *Engine) streamModelPVC(ctx context.Context, runID string, o spec.Operation, v *bundle.Verified, beforeVerification func() error) (string, error) {
	if !spec.ValidDigest(e.Site.Spec.HelperImage) {
		return "", spec.Err(16, "native model staging requires an independently admitted exact helper manifest digest")
	}
	if o.Image != "" || len(o.Args) != 0 || len(o.SecretRefs) != 0 {
		return "", spec.Err(10, "native model staging uses only the fixed helper, not carrier image, arguments or secrets")
	}
	manifest, err := e.modelVolumeManifest(ctx, runID, o, v)
	if err != nil {
		return "", err
	}
	image, err := e.image(v, e.Site.Spec.HelperImage)
	if err != nil {
		return "", err
	}
	timeout := o.TimeoutSeconds
	if timeout <= 0 {
		timeout = 300
	}
	args := []string{"--root", o.MountPath, "--manifest", "/cinderlock-manifest/files.json", "--timeout", strconv.FormatInt(timeout, 10) + "s"}
	if o.ModelSubPath != "" {
		args = append(args, "--subpath", o.ModelSubPath)
	}
	options := &jobOptions{ManifestConfigMap: manifest, IntentStepID: o.ID, AttemptScoped: true, Input: func(ctx context.Context, w state.Worker) error { return e.sendModel(ctx, w, v, o.Asset, timeout) }}
	name, err := e.executeJobWithOptions(ctx, runID, o.ID, image, []string{"/usr/local/bin/cinderlock", "helper", "receive-model"}, args, nil, o.PVC, o.MountPath, timeout, options)
	if err != nil {
		return name, err
	}
	intent, err := e.Store.LatestOperation(ctx, runID, o.ID)
	if err != nil {
		return name, err
	}
	worker, err := e.operationWorker(ctx, runID, o.ID, intent.Attempt, o.ID)
	if err != nil {
		return name, err
	}
	status, err := e.modelReceiverStatus(ctx, worker)
	if err != nil || status != "complete" {
		return name, spec.Err(13, "native receiver completion cannot be established: %v", err)
	}
	if _, err = e.verifySeed(ctx, runID, o, v, beforeVerification); err != nil {
		return name, err
	}
	return name, nil
}

func nativeMountSupported(mount string) bool {
	return mount != "" && path.IsAbs(mount) && path.Clean(mount) == mount && mount != "/" && mount != "/tmp" && !strings.ContainsRune(mount, '\x00') && mount != "/cinderlock-manifest" && !strings.HasPrefix(mount, "/cinderlock-manifest/") && mount != "/usr/local/bin/cinderlock" && !strings.HasPrefix("/usr/local/bin/cinderlock", mount+"/")
}

// nativeAttemptStatus permits an explicit new attempt only after every original
// worker is terminal, including the actual receiver Pod admitted before attach.
// No missing identity is treated as evidence that a worker stopped.
func (e *Engine) nativeAttemptStatus(ctx context.Context, attempt state.Operation) (string, error) {
	workers, err := e.Store.Workers(ctx, attempt.RunID)
	if err != nil {
		return "unknown", err
	}
	result, found := "complete", false
	for _, worker := range workers {
		if worker.StepID != attempt.StepID || worker.Attempt != attempt.Attempt {
			continue
		}
		status, err := e.inspectWorker(ctx, worker)
		if err != nil {
			return "unknown", err
		}
		if status != "complete" && status != "failed" {
			return "unknown", spec.Err(13, "original native staging worker is running or unobservable; no new attempt is started")
		}
		if worker.Role == attempt.StepID {
			found = true
			podStatus, err := e.modelReceiverStatus(ctx, worker)
			if err != nil {
				return "unknown", err
			}
			if podStatus != "complete" && podStatus != "failed" {
				return "unknown", spec.Err(13, "original native receiver Pod is still running; no new attempt is started")
			}
			if podStatus == "failed" {
				result = "failed"
			}
		}
		if status == "failed" {
			result = "failed"
		}
	}
	if !found {
		return "unknown", spec.Err(13, "native staging has no durable original Job and Pod identity; explicit external reconciliation is required")
	}
	return result, nil
}

func (e *Engine) sendModel(ctx context.Context, w state.Worker, v *bundle.Verified, assetID string, seconds int64) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds+10)*time.Second)
	defer cancel()
	pod, recipe, err := e.waitModelReceiver(ctx, w)
	if err != nil {
		return err
	}
	receiver := state.ModelReceiver{Worker: w, PodName: pod.Name, PodUID: string(pod.UID), RecipeDigest: recipe}
	if err = e.Store.BindModelReceiver(ctx, receiver); err != nil {
		return spec.Err(13, "native receiver cannot be bound for its single attachment: %v", err)
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { err := modelstage.Send(ctx, v, assetID, writer); writer.CloseWithError(err); done <- err }()
	stdout, stderr := &limitedBuffer{limit: 16 << 10}, &limitedBuffer{limit: 16 << 10}
	err = e.attachModel(ctx, pod.Name, reader, stdout, stderr)
	reader.CloseWithError(io.ErrClosedPipe)
	sendErr := <-done
	if err != nil {
		return spec.Err(13, "Kubernetes model attachment ended without a confirmed result")
	}
	if sendErr != nil {
		return spec.Err(13, "verified model stream did not finish: %v", sendErr)
	}
	_, err = e.readModelReceiver(ctx, receiver)
	return err
}

func (e *Engine) attachModel(ctx context.Context, pod string, stdin io.Reader, stdout, stderr io.Writer) error {
	if e.ModelAttach != nil {
		return e.ModelAttach(ctx, pod, stdin, stdout, stderr)
	}
	if e.Kube.Client.CoreV1().RESTClient() == nil {
		return spec.Err(13, "Kubernetes attach transport is unavailable")
	}
	url := e.Kube.Client.CoreV1().RESTClient().Post().Namespace(e.Site.Spec.Namespace).Resource("pods").Name(pod).SubResource("attach").VersionedParams(&corev1.PodAttachOptions{Container: "operation", Stdin: true, Stdout: true, Stderr: true, TTY: false}, scheme.ParameterCodec).URL()
	transport, upgrader, err := spdy.RoundTripperFor(e.Kube.Config)
	if err != nil {
		return err
	}
	executor, err := remotecommand.NewSPDYExecutorRejectRedirects(transport, upgrader, http.MethodPost, url)
	if err != nil {
		return err
	}
	return executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: stdin, Stdout: stdout, Stderr: stderr, Tty: false})
}

func (e *Engine) waitModelReceiver(ctx context.Context, w state.Worker) (*corev1.Pod, string, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := e.inspectWorker(ctx, w)
		if err != nil {
			return nil, "", err
		}
		if status != "running" {
			return nil, "", spec.Err(13, "native receiver Job became terminal before its attachment")
		}
		job, err := e.Kube.Client.BatchV1().Jobs(e.Site.Spec.Namespace).Get(ctx, w.Name, metav1.GetOptions{})
		if err != nil {
			return nil, "", err
		}
		pods, err := e.Kube.Client.CoreV1().Pods(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "cinderlock.dev/run=" + w.RunID + ",cinderlock.dev/step=" + fingerprint(w.Role)[7:23]})
		if err != nil {
			return nil, "", err
		}
		controlled := []corev1.Pod{}
		for _, pod := range pods.Items {
			owner := metav1.GetControllerOf(&pod)
			if owner != nil && owner.UID == job.UID {
				controlled = append(controlled, pod)
			}
		}
		if len(controlled) > 1 {
			return nil, "", spec.Err(13, "native receiver has multiple candidate Pods")
		}
		if len(controlled) == 1 {
			pod := &controlled[0]
			recipe, err := workerPodRecipe(job, pod, w)
			if err != nil {
				return nil, "", err
			}
			if pod.Status.Phase == corev1.PodRunning && len(pod.Status.ContainerStatuses) == 1 && pod.Status.ContainerStatuses[0].Name == "operation" && pod.Status.ContainerStatuses[0].State.Running != nil {
				return pod, recipe, nil
			}
			if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
				return nil, "", spec.Err(13, "native receiver Pod terminated before attachment")
			}
		}
		select {
		case <-ctx.Done():
			return nil, "", spec.Err(13, "native receiver did not become attachable before the local deadline")
		case <-ticker.C:
		}
	}
}

func (e *Engine) readModelReceiver(ctx context.Context, r state.ModelReceiver) (*corev1.Pod, error) {
	if _, err := e.inspectWorker(ctx, r.Worker); err != nil {
		return nil, err
	}
	job, err := e.Kube.Client.BatchV1().Jobs(e.Site.Spec.Namespace).Get(ctx, r.Worker.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	pod, err := e.Kube.Client.CoreV1().Pods(e.Site.Spec.Namespace).Get(ctx, r.PodName, metav1.GetOptions{})
	if err != nil {
		return nil, spec.Err(13, "recorded native receiver Pod cannot be observed")
	}
	digest, err := workerPodRecipe(job, pod, r.Worker)
	if err != nil || string(pod.UID) != r.PodUID || digest != r.RecipeDigest {
		return nil, spec.Err(13, "native receiver Pod UID or recipe changed after attachment admission")
	}
	return pod, nil
}

func (e *Engine) modelReceiverStatus(ctx context.Context, w state.Worker) (string, error) {
	r, err := e.Store.ModelReceiver(ctx, w)
	if err != nil {
		return "unknown", spec.Err(13, "native receiver attachment has no durable Pod identity")
	}
	pod, err := e.readModelReceiver(ctx, r)
	if err != nil {
		return "unknown", err
	}
	if len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].Name != "operation" {
		return "unknown", spec.Err(13, "native receiver container status is unavailable")
	}
	terminated := pod.Status.ContainerStatuses[0].State.Terminated
	if terminated == nil {
		return "running", nil
	}
	if terminated.ExitCode == 0 && pod.Status.Phase == corev1.PodSucceeded {
		return "complete", nil
	}
	if pod.Status.Phase == corev1.PodFailed {
		return "failed", nil
	}
	return "unknown", spec.Err(13, "native receiver Pod termination is inconclusive")
}

func (e *Engine) nativeWorkerQuiescent(ctx context.Context, w state.Worker) error {
	_, err := e.Store.ModelReceiver(ctx, w)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	status, err := e.modelReceiverStatus(ctx, w)
	if err != nil {
		return err
	}
	if status != "complete" && status != "failed" {
		return spec.Err(13, "native receiver is still running; recovery cannot race its writes")
	}
	return nil
}
