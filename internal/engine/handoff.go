package engine

import (
	"context"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (e *Engine) handoffPredecessor(ctx context.Context, p spec.Plan) (state.Run, *corev1.ConfigMap, error) {
	var empty state.Run
	source, err := e.Store.Run(ctx, p.SourceRun)
	var original spec.Plan
	var site spec.Site
	if err != nil || source.ID == "" || source.TargetID != p.Snapshot.TargetID || source.Application != p.Metadata.Application || source.Namespace != e.Site.Spec.Namespace || spec.Decode(source.Plan, &original) != nil || spec.Decode(source.Site, &site) != nil {
		return empty, nil, spec.Err(13, "handoff predecessor does not bind the original application target")
	}
	if p.Kind == "RecoveryPlan" && source.BundleDigest != p.BundleDigest {
		return empty, nil, spec.Err(12, "recovery bundle differs from the original failed recipe")
	}
	digest, err := spec.Digest(original)
	if err != nil || digest != source.PlanDigest || original.BundleDigest != source.BundleDigest || original.Snapshot.TargetID != source.TargetID || original.Snapshot.NamespaceUID != p.Snapshot.NamespaceUID || site.Spec.ReleaseName != e.Site.Spec.ReleaseName || site.Spec.Namespace != e.Site.Spec.Namespace {
		return empty, nil, spec.Err(13, "handoff predecessor differs from its saved Plan, namespace or release binding")
	}
	cm, err := e.readClusterRecord(ctx, source.ID, source.PlanDigest)
	return source, cm, err
}

func (e *Engine) verifyHandoffAdmission(ctx context.Context, p spec.Plan) error {
	source, cm, err := e.handoffPredecessor(ctx, p)
	if err != nil {
		return err
	}
	if !source.Active || clusterRunResolved(cm.Data["state"]) {
		return spec.Err(13, "predecessor no longer holds the unresolved local and cluster gates")
	}
	return nil
}

// The local transaction records the edge before either cluster journal write.
func (e *Engine) handoffSource(ctx context.Context, record state.Run, p spec.Plan) (state.Run, *corev1.ConfigMap, error) {
	var empty state.Run
	source, cm, err := e.handoffPredecessor(ctx, p)
	if err != nil {
		return empty, nil, err
	}
	if !record.Active || source.Active || source.ID == record.ID || source.TargetID != record.TargetID || source.Application != record.Application || source.Namespace != record.Namespace {
		return empty, nil, spec.Err(13, "recorded handoff no longer binds an inactive predecessor and active successor")
	}
	successor, err := e.Store.Successor(ctx, source.ID)
	if err != nil || successor != record.ID {
		return empty, nil, spec.Err(13, "exact committed predecessor handoff edge is unavailable")
	}
	if cm.Data["state"] == "superseded" {
		var edge map[string]string
		if spec.Decode([]byte(cm.Data["operation"]), &edge) != nil || edge["recoveryRun"] != record.ID {
			return empty, nil, spec.Err(13, "cluster predecessor records a different successor")
		}
	} else if clusterRunResolved(cm.Data["state"]) {
		return empty, nil, spec.Err(13, "cluster predecessor no longer holds an unresolved gate")
	}
	return source, cm, nil
}

func (e *Engine) completeHandoff(ctx context.Context, record state.Run, p spec.Plan) error {
	if p.Kind == "RecoveryPlan" {
		if err := e.recoveryQuiescent(ctx, p.SourceRun); err != nil {
			return err
		}
	}
	source, predecessor, err := e.handoffSource(ctx, record, p)
	if err != nil {
		return err
	}
	_, err = e.Kube.Client.CoreV1().ConfigMaps(e.Site.Spec.Namespace).Get(ctx, "cinderlock-run-"+record.ID, metav1.GetOptions{})
	missing := apierrors.IsNotFound(err)
	if err != nil && !missing {
		return err
	}
	if missing || predecessor.Data["state"] != "superseded" {
		attempts, err := e.Store.Operations(ctx, record.ID)
		if err != nil {
			return err
		}
		workers, err := e.Store.Workers(ctx, record.ID)
		if err != nil {
			return err
		}
		if len(attempts) != 0 || len(workers) != 0 {
			return spec.Err(13, "unfinished cluster handoff cannot explain successor worker effects")
		}
	}
	if missing {
		if err := e.clusterRecord(ctx, record.ID, record.PlanDigest, "acquiring", nil); err != nil {
			return err
		}
	} else if err := e.verifyClusterRecord(ctx, record.ID, record.PlanDigest); err != nil {
		return err
	}
	if predecessor.Data["state"] != "superseded" {
		return e.clusterRecord(ctx, source.ID, source.PlanDigest, "superseded", map[string]string{"recoveryRun": record.ID})
	}
	return nil
}
