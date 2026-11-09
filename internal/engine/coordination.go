package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	coordv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type coordinator struct {
	e                   *Engine
	name, holder, runID string
	mu                  sync.Mutex
	lost                error
	cancel              context.CancelFunc
	done                chan struct{}
}

func (e *Engine) acquire(ctx context.Context, runID string, recoverySource ...string) (*coordinator, error) {
	records, err := e.Kube.Client.CoreV1().ConfigMaps(e.Site.Spec.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/managed-by=cinderlock"})
	if err != nil {
		return nil, err
	}
	for _, record := range records.Items {
		if record.Data["releaseName"] != e.Site.Spec.ReleaseName || record.Data["runID"] == runID || (len(recoverySource) == 1 && recoverySource[0] != "" && record.Data["runID"] == recoverySource[0]) {
			continue
		}
		status := record.Data["state"]
		if status != "succeeded" && status != "recovered" && status != "superseded" && status != "probe_complete" && status != "probe_failed" && status != "retired" && status != "artifacts_staged" && status != "artifacts_failed" && status != "gitops_prepared" && status != "gitops_prepare_failed" {
			return nil, spec.Err(18, "cluster records an unresolved prior run %s", record.Data["runID"])
		}
	}
	name := "cinderlock-" + fingerprint(e.Site.Spec.ReleaseName)[7:27]
	holder := runID + "/" + randomID()
	duration := int32(30)
	stamp := metav1.NewMicroTime(time.Now().UTC())
	lease := &coordv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: e.Site.Spec.Namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "cinderlock"}}, Spec: coordv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, AcquireTime: &stamp, RenewTime: &stamp}}
	_, err = e.Kube.Client.CoordinationV1().Leases(e.Site.Spec.Namespace).Create(ctx, lease, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil, spec.Err(18, "application coordination lease exists; expiry alone cannot authorize takeover; inspect prior run and establish quiescence before customer-managed release")
		}
		return nil, err
	}
	child, cancel := context.WithCancel(context.Background())
	c := &coordinator{e: e, name: name, holder: holder, runID: runID, cancel: cancel, done: make(chan struct{})}
	go c.renew(child)
	return c, nil
}

func (c *coordinator) renew(ctx context.Context) {
	defer close(c.done)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			request, cancel := context.WithTimeout(ctx, 5*time.Second)
			lease, err := c.e.Kube.Client.CoordinationV1().Leases(c.e.Site.Spec.Namespace).Get(request, c.name, metav1.GetOptions{})
			if err == nil && (lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != c.holder) {
				err = errors.New("lease holder changed")
			}
			if err == nil {
				stamp := metav1.NewMicroTime(time.Now().UTC())
				lease.Spec.RenewTime = &stamp
				_, err = c.e.Kube.Client.CoordinationV1().Leases(c.e.Site.Spec.Namespace).Update(request, lease, metav1.UpdateOptions{})
			}
			cancel()
			if err != nil {
				c.mu.Lock()
				c.lost = err
				c.mu.Unlock()
				return
			}
		}
	}
}

func (c *coordinator) check(ctx context.Context) error {
	c.mu.Lock()
	lost := c.lost
	c.mu.Unlock()
	if lost != nil {
		return spec.Err(18, "coordination lease lost; no further mutations: %v", lost)
	}
	l, err := c.e.Kube.Client.CoordinationV1().Leases(c.e.Site.Spec.Namespace).Get(ctx, c.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if l.Spec.HolderIdentity == nil || *l.Spec.HolderIdentity != c.holder {
		return spec.Err(18, "coordination holder no longer matches run")
	}
	return nil
}

func (c *coordinator) release(ctx context.Context) error {
	c.cancel()
	<-c.done
	l, err := c.e.Kube.Client.CoordinationV1().Leases(c.e.Site.Spec.Namespace).Get(ctx, c.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if l.Spec.HolderIdentity == nil || *l.Spec.HolderIdentity != c.holder {
		return errors.New("cannot release another holder's coordination lease")
	}
	uid := l.UID
	rv := l.ResourceVersion
	return c.e.Kube.Client.CoordinationV1().Leases(c.e.Site.Spec.Namespace).Delete(ctx, c.name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
}

func (e *Engine) clusterRecord(ctx context.Context, runID, planDigest, status string, operation any) error {
	name := "cinderlock-run-" + runID
	b, err := json.Marshal(operation)
	if err != nil {
		return err
	}
	if result, ok := operation.(spec.RunResult); ok {
		summary := struct {
			Kind          string            `json:"kind"`
			Version       int               `json:"version"`
			State         string            `json:"state"`
			Acceptance    string            `json:"acceptance"`
			Domains       map[string]string `json:"domains"`
			ResultDigest  string            `json:"resultDigest"`
			ResultBytes   int               `json:"resultBytes"`
			Evidence      string            `json:"evidence"`
			CheckCount    int               `json:"checkCount"`
			PassedChecks  int               `json:"passedChecks"`
			FailedChecks  int               `json:"failedChecks"`
			BlockedChecks int               `json:"blockedChecks"`
			OtherChecks   int               `json:"otherChecks"`
		}{Kind: "RunJournalSummary", Version: 1, State: result.State, Acceptance: result.Acceptance, Domains: result.Domains, ResultDigest: spec.Hash(b), ResultBytes: len(b), Evidence: "operator-journal", CheckCount: len(result.Checks)}
		for _, check := range result.Checks {
			switch check.Status {
			case "pass":
				summary.PassedChecks++
			case "fail":
				summary.FailedChecks++
			case "blocked":
				summary.BlockedChecks++
			default:
				summary.OtherChecks++
			}
		}
		b, err = json.Marshal(summary)
		if err != nil {
			return err
		}
	}
	if len(b) > 256<<10 {
		return errors.New("cluster intent exceeds bounded journal size")
	}
	data := map[string]string{"runID": runID, "releaseName": e.Site.Spec.ReleaseName, "planDigest": planDigest, "state": status, "operation": string(b), "updatedAt": spec.Now()}
	cms := e.Kube.Client.CoreV1().ConfigMaps(e.Site.Spec.Namespace)
	cm, err := cms.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = cms.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: e.Site.Spec.Namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "cinderlock", "cinderlock.dev/run": runID}}, Data: data}, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if cm.Data["planDigest"] != planDigest {
		return spec.Err(13, "cluster run journal plan binding conflicts")
	}
	cm.Data = data
	_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

func (e *Engine) verifyClusterRecord(ctx context.Context, runID, planDigest string) error {
	cm, err := e.Kube.Client.CoreV1().ConfigMaps(e.Site.Spec.Namespace).Get(ctx, "cinderlock-run-"+runID, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("cluster journal unavailable; refusing new mutations: %w", err)
	}
	if cm.Data["runID"] != runID || cm.Data["planDigest"] != planDigest {
		return spec.Err(13, "cluster journal binding mismatch")
	}
	return nil
}

func deletionPreconditions(uid types.UID, version string) *metav1.Preconditions {
	return &metav1.Preconditions{UID: &uid, ResourceVersion: &version}
}
