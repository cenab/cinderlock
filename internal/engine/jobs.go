package engine

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/modelstage"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func jobName(runID, step string) string {
	return "cl-" + runID[:min(16, len(runID))] + "-" + fingerprint(step)[7:23]
}

type jobOptions struct {
	AttemptScoped     bool
	Input             func(context.Context, state.Worker) error
	NodeName          string
	NodeUID           string
	BundleDigest      string
	Profile           string
	GPUCount          int64
	ReadOnlyPVC       bool
	ManifestConfigMap string
	IntentStepID      string
	Fixtures          []fixtureBinding
}

func (e *Engine) executeJob(ctx context.Context, runID, stepID, image string, command, args, secretRefs []string, pvc, mount string, timeout int64) (string, error) {
	return e.executeJobWithOptions(ctx, runID, stepID, image, command, args, secretRefs, pvc, mount, timeout, nil)
}

func (e *Engine) executeJobWithOptions(ctx context.Context, runID, stepID, image string, command, args, secretRefs []string, pvc, mount string, timeout int64, options *jobOptions) (string, error) {
	if len(command) == 0 {
		return "", spec.Err(10, "Job entrypoint is required")
	}
	if timeout <= 0 {
		timeout = 300
	}
	if timeout > 86400 {
		return "", spec.Err(2, "Job timeout exceeds one day")
	}
	name := jobName(runID, stepID)
	zero := int32(0)
	uid := int64(10001)
	yes := true
	no := false
	container := corev1.Container{Name: "operation", Image: image, ImagePullPolicy: corev1.PullIfNotPresent, Command: command, Args: args, Env: []corev1.EnvVar{{Name: "CINDERLOCK_RUN_ID", Value: runID}, {Name: "CINDERLOCK_OPERATION_ID", Value: runID + "/" + stepID}}, SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &yes, RunAsUser: &uid, AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}, Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")}}, VolumeMounts: []corev1.VolumeMount{{Name: "temporary", MountPath: "/tmp"}}}
	if options != nil && options.Input != nil {
		container.Stdin = true
		container.StdinOnce = true
	}
	for _, refID := range secretRefs {
		ref, ok := e.Site.Spec.SecretRefs[refID]
		if !ok {
			return name, spec.Err(10, "missing Job secret reference %q", refID)
		}
		if ref.File != "" {
			return name, spec.Err(10, "local-file Job secret injection is not supported; supply a customer-managed Kubernetes Secret")
		}
		if ref.Key == "" || ref.Name == "" {
			return name, spec.Err(2, "Job secret needs explicit name and key")
		}
		if ref.Namespace != "" && ref.Namespace != e.Site.Spec.Namespace {
			return name, spec.Err(16, "cross-namespace Job secret blocked")
		}
		envName := strings.ToUpper(strings.ReplaceAll(refID, "-", "_"))
		if reservedJobEnvironment(envName) {
			return name, spec.Err(10, "Job secret name conflicts with fixed execution provenance")
		}
		container.Env = append(container.Env, corev1.EnvVar{Name: envName, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: ref.Name}, Key: ref.Key}}})
	}
	limit := resource.MustParse("16Mi")
	volumes := []corev1.Volume{{Name: "temporary", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &limit}}}}
	if pvc != "" {
		if mount == "" || !strings.HasPrefix(mount, "/") || mount == "/" {
			return name, spec.Err(2, "PVC mount path must be an absolute non-root path")
		}
		readOnly := options != nil && options.ReadOnlyPVC
		volumes = append(volumes, corev1.Volume{Name: "model", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: pvc, ReadOnly: readOnly}}})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{Name: "model", MountPath: mount, ReadOnly: readOnly})
	}
	if options != nil && options.ManifestConfigMap != "" {
		volumes = append(volumes, corev1.Volume{Name: "manifest", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: options.ManifestConfigMap}}}})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{Name: "manifest", MountPath: "/cinderlock-manifest", ReadOnly: true})
		provenance, err := e.modelJobProvenance(ctx, pvc, options.ManifestConfigMap)
		if err != nil {
			return name, err
		}
		container.Env = append(container.Env, corev1.EnvVar{Name: modelEnvironment, Value: provenance})
	}
	if options != nil {
		if err := appendFixtureVolumes(&container, &volumes, options.Fixtures); err != nil {
			return name, err
		}
	}
	labels := map[string]string{"app.kubernetes.io/managed-by": "cinderlock", "cinderlock.dev/run": runID, "cinderlock.dev/step": fingerprint(stepID)[7:23]}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: e.Site.Spec.Namespace, Labels: labels}, Spec: batchv1.JobSpec{BackoffLimit: &zero, ActiveDeadlineSeconds: &timeout, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever, AutomountServiceAccountToken: &no, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &uid, FSGroup: &uid, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}, Containers: []corev1.Container{container}, Volumes: volumes}}}}
	if options != nil && (options.GPUCount > 0 || options.NodeName != "") {
		job.Annotations = map[string]string{"cinderlock.dev/node-uid": options.NodeUID, "cinderlock.dev/bundle-digest": options.BundleDigest, "cinderlock.dev/profile": options.Profile}
		if options.GPUCount < 1 || options.NodeName == "" {
			return name, spec.Err(2, "GPU probe needs explicit node and positive device count")
		}
		q := *resource.NewQuantity(options.GPUCount, resource.DecimalSI)
		job.Spec.Template.Spec.Containers[0].Resources.Limits[corev1.ResourceName("nvidia.com/gpu")] = q
		job.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceName("nvidia.com/gpu")] = q
		job.Spec.Template.Spec.Affinity = &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{options.NodeName}}}}}}}}
	}
	for _, name := range e.Site.Spec.ImagePullSecrets {
		job.Spec.Template.Spec.ImagePullSecrets = append(job.Spec.Template.Spec.ImagePullSecrets, corev1.LocalObjectReference{Name: name})
	}
	intentStepID := stepID
	if options != nil && options.IntentStepID != "" {
		intentStepID = options.IntentStepID
	}
	if e.Store == nil {
		return name, spec.Err(13, "Job requires a durable operation intent")
	}
	intent, err := e.Store.LatestOperation(ctx, runID, intentStepID)
	if err != nil || intent.State != "intent" && intent.State != "uncertain" {
		return name, spec.Err(13, "Job requires its unresolved durable operation intent")
	}
	if options != nil && options.AttemptScoped {
		name = jobName(runID, stepID+"/attempt/"+strconv.Itoa(intent.Attempt))
		job.Name = name
	}
	recipe, err := jobRecipe(job)
	if err != nil {
		return name, err
	}
	if job.Annotations == nil {
		job.Annotations = map[string]string{}
	}
	job.Annotations["cinderlock.dev/recipe-digest"] = recipe
	worker, workerErr := e.Store.Worker(ctx, runID, intentStepID, intent.Attempt, stepID)
	if workerErr == nil {
		if worker.Name != name || worker.RecipeDigest != recipe {
			return name, spec.Err(13, "recorded worker differs from current fixed Job recipe")
		}
		return name, e.waitWorker(ctx, worker, time.Duration(timeout)*time.Second)
	}
	if !errors.Is(workerErr, sql.ErrNoRows) {
		return name, workerErr
	}
	created, err := e.Kube.Client.BatchV1().Jobs(e.Site.Spec.Namespace).Create(ctx, job, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return name, spec.Err(13, "Job exists without a recorded server UID; name and labels cannot establish original identity")
	}
	if err != nil {
		if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) || apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) {
			return name, spec.Err(14, "Job creation was rejected before execution")
		}
		return name, spec.Err(13, "Job creation response is ambiguous; the server may have accepted the worker: %v", err)
	}
	if created == nil || created.UID == "" {
		return name, spec.Err(13, "created Job server UID was not returned")
	}
	worker = state.Worker{RunID: runID, StepID: intentStepID, Attempt: intent.Attempt, Role: stepID, Name: name, UID: string(created.UID), RecipeDigest: recipe}
	persist, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = e.Store.BindWorker(persist, worker)
	cancel()
	if err != nil {
		return name, spec.Err(13, "created Job identity could not be durably recorded: %v", err)
	}
	if options != nil && options.Input != nil {
		if err := options.Input(ctx, worker); err != nil {
			return name, spec.Err(13, "model attachment outcome requires reconciliation: %v", err)
		}
	}
	return name, e.waitWorker(ctx, worker, time.Duration(timeout)*time.Second)
}

func (e *Engine) waitWorker(ctx context.Context, worker state.Worker, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout+10*time.Second)
	defer cancel()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := e.inspectWorker(ctx, worker)
		if err != nil {
			return err
		}
		if status == "complete" {
			return nil
		}
		if status == "failed" {
			return spec.Err(14, "Job failed with a recorded terminal condition")
		}
		select {
		case <-ctx.Done():
			return spec.Err(13, "Job may still be running after local wait ended; reconcile before retry")
		case <-ticker.C:
		}
	}
}

func (e *Engine) waitDeployment(ctx context.Context, name string, seconds int64, runID, uid string) error {
	if seconds <= 0 {
		seconds = 300
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		d, err := e.Kube.Client.AppsV1().Deployments(e.Site.Spec.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return spec.Err(13, "restart readiness cannot be observed: %v", err)
		}
		if string(d.UID) != uid || d.Spec.Template.Annotations["cinderlock.dev/restart-run"] != runID {
			return spec.Err(11, "restart Deployment identity or requested template changed during rollout")
		}
		if deploymentRolledOut(d) {
			if d.Spec.Selector == nil {
				return spec.Err(10, "Deployment selector unavailable for restart verification")
			}
			selector, err := metav1.LabelSelectorAsSelector(d.Spec.Selector)
			if err != nil {
				return err
			}
			pods, err := e.Kube.Client.CoreV1().Pods(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
			if err != nil {
				return err
			}
			ready := int32(len(pods.Items)) == replicas(d.Spec.Replicas)
			for _, pod := range pods.Items {
				podReady := false
				for _, condition := range pod.Status.Conditions {
					if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
						podReady = true
					}
				}
				if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Annotations["cinderlock.dev/restart-run"] != runID || !podReady {
					ready = false
				}
			}
			if ready {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return spec.Err(14, "restarted Deployment did not become ready within its declared wait")
		case <-ticker.C:
		}
	}
}

func (e *Engine) check(ctx context.Context, runID string, c spec.Check, v *bundle.Verified) spec.CheckResult {
	start := time.Now()
	result := spec.CheckResult{ID: c.ID, Domain: c.Domain, Required: c.Required, Status: "blocked"}
	if result.Domain == "" {
		result.Domain = "workflow"
	}
	var fixturePlan spec.Plan
	var fixtures []fixtureBinding
	if len(c.Fixtures) > 0 {
		var err error
		fixturePlan, err = e.fixtureRunPlan(ctx, runID)
		if err == nil {
			fixtures, err = e.resolveFixtureBindings(ctx, runID, fixturePlan, c, v)
		}
		if err != nil {
			result.Reason = err.Error()
			return result
		}
	}
	ref := c.Image
	if ref == "" {
		ref = e.Site.Spec.HelperImage
	}
	image, err := e.image(v, ref)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	command := c.Command
	args := []string{}
	if c.Type == "http" {
		u, err := url.Parse(c.URL)
		if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			result.Reason = "HTTP check URL is invalid"
			return result
		}
		if !slices.Contains(e.Site.Spec.AllowedHosts, u.Hostname()) {
			result.Reason = "HTTP destination is not in the customer-approved host allowlist"
			return result
		}
		method := c.Method
		if method == "" {
			method = "GET"
		}
		if method != "GET" && method != "HEAD" {
			result.Reason = "state-changing HTTP checks require an explicit staged Job recipe"
			return result
		}
		status := c.ExpectedStatus
		if status == 0 {
			status = 200
		}
		command = []string{"/bin/sh", "-ec", `status=$(curl --silent --show-error --max-time "$4" --max-filesize 1048576 --request "$5" --output /tmp/check-body --write-out '%{http_code}' -- "$1"); test "$status" = "$2"; if test -n "$3"; then grep -F -- "$3" /tmp/check-body >/dev/null; fi`, "--"}
		timeout := c.TimeoutSeconds
		if timeout <= 0 {
			timeout = 30
		}
		args = []string{c.URL, strconv.Itoa(status), c.BodyContains, strconv.FormatInt(timeout, 10), method}
	} else if c.Type != "job" {
		result.Reason = "unsupported check type: " + c.Type
		return result
	}
	if c.ExpectedExitCode != 0 {
		result.Reason = "nonzero expected Job exit codes require a separately qualified result adapter"
		return result
	}
	stepID := checkStepID(c.ID)
	intent, priorErr := e.Store.LatestOperation(ctx, runID, stepID)
	if priorErr == nil {
		if err := checkIntentMatches(intent.Intent, c); err != nil {
			result.Reason = err.Error()
			return result
		}
		if len(c.Fixtures) > 0 {
			priorFixtures, err := fixtureIntentBindings(intent.Intent)
			actual, actualErr := spec.Digest(priorFixtures)
			expected, expectedErr := spec.Digest(fixtures)
			if err != nil || actualErr != nil || expectedErr != nil || actual != expected {
				result.Reason = "recorded acceptance fixtures differ from current seed provenance"
				return result
			}
			if err := e.validateCheckFixtures(ctx, runID, fixturePlan, c, fixtures, true); err != nil {
				result.Reason = err.Error()
				return result
			}
		}
		worker, err := e.operationWorker(ctx, runID, stepID, intent.Attempt, stepID)
		if err != nil {
			result.Reason = err.Error()
			return result
		}
		status, err := e.inspectWorker(ctx, worker)
		result.Evidence = "job/" + worker.Name
		if err == nil && intent.State == "complete" && status == "complete" {
			result.Status = "pass"
			return result
		}
		result.Reason = "prior acceptance worker must be reconciled or recovered; no duplicate is started"
		if err != nil {
			result.Reason = err.Error()
		}
		if intent.State == "failed" {
			result.Status = "fail"
		}
		return result
	}
	if !errors.Is(priorErr, sql.ErrNoRows) {
		result.Reason = priorErr.Error()
		return result
	}
	intent, err = e.Store.Intent(ctx, runID, stepID, checkIntent{Type: "check", Check: c, Fixtures: fixtures}, jobName(runID, stepID))
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	run, err := e.Store.Run(ctx, runID)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	if err := e.clusterRecord(ctx, runID, run.PlanDigest, "check_intent", intent); err != nil {
		result.Reason = err.Error()
		return result
	}
	external := ""
	applicationAttempted := false
	if len(fixtures) > 0 {
		err = e.verifyCheckFixtures(ctx, runID, c, fixtures, v)
	}
	if err == nil {
		applicationAttempted = true
		external, err = e.executeJobWithOptions(ctx, runID, stepID, image, command, args, c.SecretRefs, "", "", c.TimeoutSeconds, &jobOptions{Fixtures: fixtures})
	}
	if err == nil && len(fixtures) > 0 {
		err = e.validateCheckFixtures(ctx, runID, fixturePlan, c, fixtures, true)
	}
	result.DurationMillis = time.Since(start).Milliseconds()
	result.Evidence = "job/" + external
	outcome := "complete"
	if err != nil {
		result.Reason = err.Error()
		outcome = "uncertain"
		if spec.ExitCode(err) == 14 {
			result.Status = "fail"
			outcome = "failed"
		}
	} else {
		result.Status = "pass"
	}
	persist, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var evidence any = result
	if len(fixtures) > 0 && !applicationAttempted && outcome == "failed" {
		evidence = checkOutcome{CheckResult: result, AcceptanceWorker: "not_started"}
	}
	if err := e.Store.Complete(persist, intent, outcome, evidence); err != nil {
		result.Status = "blocked"
		result.Reason = "acceptance worker outcome could not be durably recorded"
		return result
	}
	if err := e.clusterRecord(persist, runID, run.PlanDigest, outcome, evidence); err != nil {
		result.Status = "blocked"
		result.Reason = "acceptance outcome cluster record could not be confirmed"
	}
	return result
}

func (e *Engine) seedPVC(ctx context.Context, runID string, o spec.Operation, v *bundle.Verified) (string, error) {
	if len(o.Command) == 0 && (!spec.ValidDigest(e.Site.Spec.HelperImage) || o.Image != "" || len(o.Args) != 0 || len(o.SecretRefs) != 0 || !nativeMountSupported(o.MountPath)) {
		return "", spec.Err(10, "native staging needs an independently pinned fixed helper and supported mount, without carrier image, arguments or secrets")
	}
	if o.ModelSubPath != "" && (o.ModelSubPath == "." || !spec.SafePath(o.ModelSubPath)) {
		return "", spec.Err(12, "model subdirectory must be confined within the PVC")
	}
	if o.PVC == "" || o.StorageBytes <= 0 {
		return "", spec.Err(10, "seed requires a distinct named PVC and explicit capacity")
	}
	a, err := v.Asset(o.Asset)
	if err != nil {
		return "", err
	}
	if _, err := modelstage.Manifest(a.Files); err != nil {
		return "", err
	}
	if _, err := e.image(v, e.Site.Spec.HelperImage); err != nil {
		return "", spec.Err(10, "model seed requires a locked Cinderlock helper image")
	}
	revision := a.Digest
	q := *resource.NewQuantity(o.StorageBytes, resource.BinarySI)
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: o.PVC, Namespace: e.Site.Spec.Namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "cinderlock"}, Annotations: map[string]string{"cinderlock.dev/model-revision": revision, "cinderlock.dev/run": runID}}, Spec: corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: q}}}}
	if o.StorageClass != "" {
		pvc.Spec.StorageClassName = &o.StorageClass
	}
	_, err = e.Kube.Client.CoreV1().PersistentVolumeClaims(e.Site.Spec.Namespace).Create(ctx, pvc, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		existing, getErr := e.Kube.Client.CoreV1().PersistentVolumeClaims(e.Site.Spec.Namespace).Get(ctx, o.PVC, metav1.GetOptions{})
		if getErr != nil {
			return "", getErr
		}
		if existing.Annotations["cinderlock.dev/model-revision"] != revision || existing.Annotations["cinderlock.dev/run"] != runID {
			return "", spec.Err(16, "seed PVC belongs to a different revision or run; existing models are protected")
		}
		err = nil
	}
	if err != nil {
		return "", err
	}
	if len(o.Command) == 0 {
		return e.streamModelPVC(ctx, runID, o, v)
	}
	image, err := e.image(v, o.Image)
	if err != nil {
		return "", err
	}
	seedJob, err := e.executeJob(ctx, runID, o.ID, image, o.Command, o.Args, o.SecretRefs, o.PVC, o.MountPath, o.TimeoutSeconds)
	if err != nil {
		return seedJob, err
	}
	if _, err := e.verifySeed(ctx, runID, o, v); err != nil {
		return seedJob, err
	}
	return seedJob, nil
}
