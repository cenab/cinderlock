package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

// checkSiteConfiguration traverses containers before accepting a declared field.
// A scalar/null at a parent cannot replace a protected descendant. An object or
// array declared as a field is atomic and owns its whole subtree.
func checkSiteConfiguration(contract *spec.ConfigurationContract, values map[string]any) error {
	rules := map[string]spec.ConfigurationField{}
	for _, field := range contract.Fields {
		rules[field.Path] = field
	}
	visited := 0
	var walk func(string, any) error
	walk = func(path string, value any) error {
		visited++
		if visited > 4096 {
			return spec.Err(10, "Site configuration exceeds supported ownership bounds")
		}
		if field, ok := rules[path]; ok {
			if field.Owner != "site" {
				return spec.Err(10, "Site configuration cannot override %s-owned field %s", field.Owner, path)
			}
			if value != nil && !configurationType(field.Type, value) {
				return spec.Err(10, "Site configuration field %s has the wrong declared type", path)
			}
			return nil
		}
		descendant := path == ""
		for rule := range rules {
			if strings.HasPrefix(rule, path+".") {
				descendant = true
				break
			}
		}
		object, ok := value.(map[string]any)
		if !descendant || !ok {
			// Don't reflect undeclared keys: a key can itself contain private data.
			return spec.Err(10, "Site configuration contains an undeclared path or replaces an ownership parent")
		}
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if !spec.ValidConfigurationPath(key) || strings.Contains(key, ".") {
				return spec.Err(10, "Site configuration keys must be explicit object segments")
			}
			child := key
			if path != "" {
				child = path + "." + key
			}
			if err := walk(child, object[key]); err != nil {
				return err
			}
		}
		return nil
	}
	return walk("", values)
}

func configurationType(kind string, value any) bool {
	switch kind {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		switch value := value.(type) {
		case float64:
			return !math.IsNaN(value) && !math.IsInf(value, 0) && value == math.Trunc(value) && math.Abs(value) <= 9007199254740991
		case int, int32, int64, uint, uint32, uint64, json.Number:
			_, err := canonicalConfigurationValue(value)
			return err == nil
		}
	case "array":
		_, ok := value.([]any)
		return ok
	case "object":
		_, ok := value.(map[string]any)
		return ok
	}
	return false
}

func canonicalConfigurationValue(value any) ([]byte, error) {
	return spec.Canonical(struct {
		Value any `json:"value"`
	}{value})
}

func configurationLookup(values map[string]any, path string) (any, bool) {
	var value any = values
	for _, part := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok = object[part]
		if !ok || value == nil {
			return nil, false
		}
	}
	return value, true
}

// mergeConfiguration mirrors Helm's ordered values-file map merge. Nulls are
// retained until chart defaults are coalesced, so a later object can restore a
// default removed by an earlier file. Arrays/scalars replace an earlier value.
func mergeConfiguration(base, overlay map[string]any) map[string]any {
	for key, value := range overlay {
		if object, ok := value.(map[string]any); ok {
			prior, _ := base[key].(map[string]any)
			if prior == nil {
				prior = map[string]any{}
			}
			base[key] = mergeConfiguration(prior, object)
		} else {
			base[key] = value
		}
	}
	return base
}

func coalesceConfiguration(defaults, overrides map[string]any) map[string]any {
	for key, value := range defaults {
		current, exists := overrides[key]
		if exists && current == nil {
			delete(overrides, key)
			continue
		}
		if !exists {
			overrides[key] = value
			continue
		}
		object, objectOK := value.(map[string]any)
		currentObject, currentOK := current.(map[string]any)
		if objectOK && currentOK {
			overrides[key] = coalesceConfiguration(object, currentObject)
		}
	}
	return overrides
}

func configurationDocument(data []byte) (map[string]any, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}, nil
	}
	var values map[string]any
	if err := spec.Decode(data, &values); err != nil || values == nil {
		return nil, spec.Err(10, "configuration requires a bounded string-keyed object with safe integer numbers")
	}
	return values, nil
}

func ownershipChartDefaults(chart string) (map[string]any, error) {
	f, err := os.Open(chart)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, spec.Err(10, "configuration ownership requires a packaged chart")
	}
	defer gz.Close()
	reader := tar.NewReader(io.LimitReader(gz, 64<<20))
	defaults := map[string]any{}
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return defaults, nil
		}
		if err != nil {
			return nil, spec.Err(10, "configuration chart cannot be inspected")
		}
		parts := strings.Split(header.Name, "/")
		if len(parts) > 1 && parts[1] == "charts" {
			return nil, spec.Err(10, "configuration ownership v1 supports a root chart without subcharts")
		}
		if len(parts) != 2 || (parts[1] != "values.yaml" && parts[1] != "Chart.yaml") {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > 4<<20 || seen[parts[1]] {
			return nil, spec.Err(10, "configuration chart metadata must be unique bounded regular files")
		}
		seen[parts[1]] = true
		data, err := io.ReadAll(io.LimitReader(reader, (4<<20)+1))
		if err != nil {
			return nil, err
		}
		values, err := configurationDocument(data)
		if err != nil {
			return nil, err
		}
		if parts[1] == "values.yaml" {
			defaults = values
		} else if dependencies, ok := values["dependencies"]; ok && dependencies != nil {
			if list, ok := dependencies.([]any); !ok || len(list) != 0 {
				return nil, spec.Err(10, "configuration ownership v1 supports a root chart without dependencies")
			}
		}
	}
}

func resolveConfigurationFiles(chart string, files []string, contract *spec.ConfigurationContract) (map[string]any, error) {
	defaults, err := ownershipChartDefaults(chart)
	if err != nil {
		return nil, err
	}
	overrides := map[string]any{}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, spec.MaxDocumentBytes+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || len(data) > spec.MaxDocumentBytes {
			return nil, spec.Err(10, "configuration values file cannot be read within supported bounds")
		}
		values, err := configurationDocument(data)
		if err != nil {
			return nil, err
		}
		mergeConfiguration(overrides, values)
	}
	resolved := coalesceConfiguration(defaults, overrides)
	for _, field := range contract.Fields {
		value, present := configurationLookup(resolved, field.Path)
		if !present {
			if field.Required {
				return nil, spec.Err(10, "required configuration field %s is absent", field.Path)
			}
			continue
		}
		if !configurationType(field.Type, value) {
			return nil, spec.Err(10, "resolved configuration field %s has the wrong declared type", field.Path)
		}
	}
	return resolved, nil
}

func (e *Engine) configurationReview(ctx context.Context, p spec.Plan, v *bundle.Verified) (*spec.ConfigurationReview, error) {
	contract := v.Index.Lock.Release.Spec.Deployment.Configuration
	review := &spec.ConfigurationReview{Ownership: "unqualified", ComparisonRevision: p.Snapshot.HelmRevision, ComparisonStatus: "not_compared", Fields: []spec.ConfigurationFieldReview{}}
	if contract == nil {
		return review, nil
	}
	review.Ownership = "enforced"
	chart, files, cleanup, err := e.helmFiles(v)
	if err != nil {
		return review, err
	}
	defer cleanup()
	resolved, err := resolveConfigurationFiles(chart, files, contract)
	if err != nil {
		return review, err
	}
	canonical, err := spec.Canonical(resolved)
	if err != nil {
		return review, spec.Err(10, "resolved configuration exceeds the supported canonical profile")
	}
	review.EffectiveDigest, err = e.privateFingerprint(append([]byte("cinderlock.configuration-effective.v1\x00"), canonical...))
	if err != nil {
		return review, err
	}
	for _, field := range contract.Fields {
		review.Fields = append(review.Fields, spec.ConfigurationFieldReview{Path: field.Path, Owner: field.Owner, Change: "not_compared"})
	}
	sortConfigurationReview(review)
	baseline := map[string]any{}
	if p.Snapshot.HelmRevision == 0 && p.Snapshot.InstalledVersion == "" {
		absent := false
		for _, fact := range p.Snapshot.Facts {
			absent = absent || fact.Name == "helm.release" && fact.Status == "absent"
		}
		if !absent {
			return review, spec.Err(10, "configuration comparison requires a conclusive Helm release observation")
		}
		review.ComparisonStatus = "not_installed"
	} else if p.Snapshot.HelmRevision > 0 {
		data, err := e.helm(ctx, "get", "values", e.Site.Spec.ReleaseName, "--revision", strconv.FormatInt(p.Snapshot.HelmRevision, 10), "--all", "--output", "json")
		if err == nil {
			baseline, err = configurationDocument(data)
		}
		if err != nil {
			return review, spec.Err(10, "configuration comparison is unavailable for the pinned Helm revision")
		}
		review.ComparisonStatus = "available"
	} else {
		return review, spec.Err(10, "configuration comparison needs an exact prior Helm revision")
	}
	for i, field := range review.Fields {
		before, had := configurationLookup(baseline, field.Path)
		after, has := configurationLookup(resolved, field.Path)
		change := "unchanged"
		switch {
		case !had && has:
			change = "added"
		case had && !has:
			change = "removed"
		case had && has:
			a, errA := canonicalConfigurationValue(before)
			b, errB := canonicalConfigurationValue(after)
			if errA != nil || errB != nil {
				return review, spec.Err(10, "configuration comparison exceeds the supported canonical profile")
			}
			if !bytes.Equal(a, b) {
				change = "changed"
			}
		}
		review.Fields[i].Change = change
	}
	return review, nil
}

func sortConfigurationReview(review *spec.ConfigurationReview) {
	sort.Slice(review.Fields, func(i, j int) bool { return review.Fields[i].Path < review.Fields[j].Path })
}

func (e *Engine) addConfigurationFindings(ctx context.Context, p *spec.Plan, v *bundle.Verified) {
	review, err := e.configurationReview(ctx, *p, v)
	p.ConfigurationReview = review
	if err != nil {
		p.Executable = false
		p.Findings = append(p.Findings, spec.Finding{Code: "CONFIGURATION_UNVERIFIED", Severity: "blocker", Message: err.Error()})
	}
}

func (e *Engine) checkConfigurationPlan(ctx context.Context, p spec.Plan, v *bundle.Verified) error {
	if gitOpsPhase(p) {
		if contract := v.Index.Lock.Release.Spec.Deployment.Configuration; contract != nil {
			return checkSiteConfiguration(contract, e.Site.Spec.Values)
		}
		return nil
	}
	if p.Kind == "ProbePlan" || p.Kind == "RetirementPlan" || p.Kind == "ArtifactsPlan" {
		return nil
	}
	if p.ConfigurationReview == nil && v.Index.Lock.Release.Spec.Deployment.Configuration == nil {
		// Existing saved plans predate the opt-in ownership contract.
		return nil
	}
	current, err := e.configurationReview(ctx, p, v)
	if err != nil {
		return err
	}
	want, err := spec.Canonical(current)
	if err != nil {
		return err
	}
	got, err := spec.Canonical(p.ConfigurationReview)
	if err != nil || !bytes.Equal(want, got) {
		return spec.Err(11, "configuration ownership, masked review, or resolved values differ from the plan")
	}
	return nil
}
