package engine

import (
	"path"
	"reflect"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func gitOpsProfileOptions(value any) bool {
	if value == nil {
		return true
	}
	options, ok := value.([]any)
	if !ok || len(options) > 3 {
		return false
	}
	seen := map[string]bool{}
	for _, option := range options {
		s, ok := option.(string)
		if !ok || seen[s] || !slices.Contains([]string{"ServerSideApply=true", "FailOnSharedResource=true", "DisableClientSideApplyMigration=true"}, s) {
			return false
		}
		seen[s] = true
	}
	return true
}

func gitOpsProfileSource(value any, c GitOpsProfileContract, signedPath string) bool {
	source, ok := value.(map[string]any)
	if !ok || !gitOpsProfileKeys(source, "repoURL", "targetRevision", "path", "directory") || source["repoURL"] != c.RepositoryURL || source["targetRevision"] != c.AcceptedRevision || source["path"] != path.Dir(signedPath) {
		return false
	}
	directory, ok := source["directory"].(map[string]any)
	if !ok || !gitOpsProfileKeys(directory, "include", "recurse", "exclude") || directory["include"] != path.Base(signedPath) {
		return false
	}
	if value, exists := directory["recurse"]; exists && value != false {
		return false
	}
	if value, exists := directory["exclude"]; exists && value != "" {
		return false
	}
	return true
}

func gitOpsProfileDestination(value any, namespace string) bool {
	destination, ok := value.(map[string]any)
	return ok && gitOpsProfileKeys(destination, "server", "namespace") && destination["server"] == "https://kubernetes.default.svc" && destination["namespace"] == namespace
}

func gitOpsProfileApplication(u *unstructured.Unstructured, c GitOpsProfileContract, namespace, signedPath string, out *GitOpsProfileObservation) bool {
	if !gitOpsProfileActive(u) || u.GetAPIVersion() != "argoproj.io/v1alpha1" || u.GetKind() != "Application" || u.GetNamespace() != c.Namespace || u.GetName() != c.Name || string(u.GetUID()) != c.UID || u.GetGeneration() <= 0 || u.Object["operation"] != nil || !gitOpsProfileMetadata(u, c, false) {
		return false
	}
	out.UID, out.ResourceVersion, out.Generation = string(u.GetUID()), u.GetResourceVersion(), u.GetGeneration()
	s, ok := u.Object["spec"].(map[string]any)
	if !ok || !gitOpsProfileKeys(s, "source", "destination", "project", "syncPolicy", "revisionHistoryLimit", "info") || !gitOpsProfileSource(s["source"], c, signedPath) || !gitOpsProfileDestination(s["destination"], namespace) {
		return false
	}
	if value, exists := s["syncPolicy"]; exists {
		p, ok := value.(map[string]any)
		if !ok || !gitOpsProfileKeys(p, "syncOptions", "automated", "retry") || !gitOpsProfileOptions(p["syncOptions"]) {
			return false
		}
		options, ok := p["syncOptions"].([]any)
		if !ok || !slices.Contains(options, any("ServerSideApply=true")) {
			return false
		}
		if auto, exists := p["automated"]; exists {
			a, ok := auto.(map[string]any)
			if !ok || !gitOpsProfileKeys(a, "enabled", "prune", "selfHeal", "allowEmpty") {
				return false
			}
			for _, v := range a {
				if _, ok := v.(bool); !ok {
					return false
				}
			}
		}
	} else {
		return false
	}
	status, ok := u.Object["status"].(map[string]any)
	if !ok || !gitOpsProfileEmptySlice(status["conditions"]) || !gitOpsProfileEmptySlice(status["warnings"]) {
		return false
	}
	if hydration := status["sourceHydrator"]; hydration != nil {
		empty, ok := hydration.(map[string]any)
		if !ok || len(empty) != 0 {
			return false
		}
	}
	if !gitOpsProfileEmptySlice(status["sourceTypes"]) {
		return false
	}
	if status["sourceType"] != "Directory" {
		return false
	}
	sync, ok := status["sync"].(map[string]any)
	if !ok || sync["revision"] != c.AcceptedRevision || sync["status"] != "Synced" || !gitOpsProfileEmptySlice(sync["revisions"]) {
		return false
	}
	compared, ok := sync["comparedTo"].(map[string]any)
	if !ok || !gitOpsProfileKeys(compared, "source", "destination") || !reflect.DeepEqual(compared["source"], s["source"]) || !reflect.DeepEqual(compared["destination"], s["destination"]) {
		return false
	}
	health, ok := status["health"].(map[string]any)
	if !ok || health["status"] != "Healthy" {
		return false
	}
	operation, ok := status["operationState"].(map[string]any)
	if !ok || operation["phase"] != "Succeeded" {
		return false
	}
	request, ok := operation["operation"].(map[string]any)
	if !ok || !gitOpsProfileKeys(request, "sync", "initiatedBy", "info", "retry") {
		return false
	}
	syncRequest, ok := request["sync"].(map[string]any)
	if !ok || !gitOpsProfileKeys(syncRequest, "revision", "prune", "dryRun", "syncStrategy", "syncOptions", "autoHealAttemptsCount") || !gitOpsProfileOptions(syncRequest["syncOptions"]) {
		return false
	}
	if revision, exists := syncRequest["revision"]; exists && revision != c.AcceptedRevision {
		return false
	}
	if dry, exists := syncRequest["dryRun"]; exists && dry != false {
		return false
	}
	if prune, exists := syncRequest["prune"]; exists {
		if _, ok := prune.(bool); !ok {
			return false
		}
	}
	if strategy, exists := syncRequest["syncStrategy"]; exists {
		m, ok := strategy.(map[string]any)
		if !ok || len(m) != 1 || !gitOpsProfileKeys(m, "apply", "hook") {
			return false
		}
		selected := m["apply"]
		if selected == nil {
			selected = m["hook"]
		}
		apply, ok := selected.(map[string]any)
		if !ok || !gitOpsProfileKeys(apply, "force") {
			return false
		}
		if force, exists := apply["force"]; exists && force != false {
			return false
		}
	}
	result, ok := operation["syncResult"].(map[string]any)
	if !ok || !gitOpsProfileKeys(result, "revision", "source", "resources") || result["revision"] != c.AcceptedRevision || !reflect.DeepEqual(result["source"], s["source"]) {
		return false
	}
	if !gitOpsProfileTimes(u, c, out) {
		return false
	}
	out.ObservedRevision, out.SyncStatus, out.HealthStatus, out.OperationPhase = c.AcceptedRevision, "Synced", "Healthy", "Succeeded"
	return true
}

func gitOpsProfileTimes(u *unstructured.Unstructured, c GitOpsProfileContract, out *GitOpsProfileObservation) bool {
	now := time.Now()
	before, _ := time.Parse(time.RFC3339Nano, c.NotBefore)
	paths := [][]string{{"status", "operationState", "startedAt"}, {"status", "operationState", "finishedAt"}, {"status", "reconciledAt"}}
	var previous time.Time
	var originals [3]string
	for i, p := range paths {
		text, found, err := unstructured.NestedString(u.Object, p...)
		timestamp, parseErr := time.Parse(time.RFC3339Nano, text)
		if err != nil || !found || parseErr != nil || timestamp.IsZero() || timestamp.Before(before) || timestamp.Before(previous) || timestamp.After(now) || now.Sub(timestamp) > time.Duration(c.MaxAgeSeconds)*time.Second {
			return false
		}
		previous, originals[i] = timestamp, text
	}
	if out != nil {
		out.OperationStartedAt, out.OperationFinishedAt, out.ReconciledAt = originals[0], originals[1], originals[2]
	}
	return true
}

func gitOpsProfileResources(application *unstructured.Unstructured, desired []*unstructured.Unstructured, out *GitOpsProfileObservation) bool {
	healthSource, _, err := unstructured.NestedString(application.Object, "status", "resourceHealthSource")
	if err != nil || healthSource != "" && healthSource != "appTree" {
		return false
	}
	byIdentity := map[string]int{}
	for i, u := range desired {
		byIdentity[u.GroupVersionKind().Group+"/"+u.GetKind()+"/"+u.GetNamespace()+"/"+u.GetName()] = i
		out.Resources = append(out.Resources, GitOpsProfileResourceObservation{APIVersion: u.GetAPIVersion(), Kind: u.GetKind(), Namespace: u.GetNamespace(), Name: u.GetName()})
	}
	for _, operation := range []bool{false, true} {
		p := []string{"status", "resources"}
		if operation {
			p = []string{"status", "operationState", "syncResult", "resources"}
		}
		resources, found, err := unstructured.NestedSlice(application.Object, p...)
		if err != nil || !found || len(resources) != len(desired) {
			return false
		}
		seen := map[string]bool{}
		for _, value := range resources {
			r, ok := value.(map[string]any)
			if !ok {
				return false
			}
			fields := []string{"group", "version", "kind", "namespace", "name", "status", "health", "hook", "requiresPruning", "requiresDeletionConfirmation", "syncWave", "wave"}
			if operation {
				fields = []string{"group", "version", "kind", "namespace", "name", "status", "message", "hookType", "hookPhase", "syncPhase", "images"}
			}
			if !gitOpsProfileKeys(r, fields...) {
				return false
			}
			identity := ""
			for _, field := range []string{"group", "kind", "namespace", "name"} {
				text, ok := r[field].(string)
				if !ok && (field != "group" || r[field] != nil) {
					return false
				}
				if field != "group" {
					identity += "/"
				}
				identity += text
			}
			i, known := byIdentity[identity]
			if !known || seen[identity] || r["status"] != "Synced" {
				return false
			}
			seen[identity] = true
			if version, exists := r["version"]; exists && version != desired[i].GroupVersionKind().Version {
				return false
			}
			fact := &out.Resources[i]
			if operation {
				if hook, exists := r["hookType"]; exists && hook != "" {
					return false
				}
				if r["syncPhase"] != "Sync" {
					return false
				}
				if phase, exists := r["hookPhase"]; exists && phase != "Succeeded" && phase != "" {
					return false
				}
				fact.OperationStatus = "Synced"
				continue
			}
			for _, flag := range []string{"hook", "requiresPruning", "requiresDeletionConfirmation"} {
				if v, exists := r[flag]; exists && v != false {
					return false
				}
			}
			for _, wave := range []string{"syncWave", "wave"} {
				if v, exists := r[wave]; exists && v != int64(0) {
					return false
				}
			}
			health, exists := r["health"]
			if exists {
				h, ok := health.(map[string]any)
				if !ok || h["status"] != "Healthy" {
					return false
				}
				fact.ControllerHealth = "Healthy"
			} else if desired[i].GetKind() == "Deployment" && healthSource != "appTree" {
				return false
			}
			fact.SyncStatus = "Synced"
		}
	}
	return true
}
