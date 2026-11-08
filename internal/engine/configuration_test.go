package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestConfigurationNestedSiteOverrideCannotReplaceVendorValue(t *testing.T) {
	e, _, _ := fixture(t)
	v := chartFixture(t, e)
	v.Index.Lock.Release.Spec.Deployment.Configuration = &spec.ConfigurationContract{Version: 1, Fields: []spec.ConfigurationField{
		{Path: "auth.token", Owner: "vendor", Type: "string"},
		{Path: "auth.realm", Owner: "site", Type: "string"},
	}}
	const private = "cust-secret-must-never-be-reported"
	e.Site.Spec.Values = map[string]any{"auth": map[string]any{"token": private, "realm": "internal"}}
	_, _, cleanup, err := e.helmFiles(v)
	if cleanup != nil {
		cleanup()
	}
	if err == nil {
		t.Fatal("nested Site override replaced a vendor-owned value")
	}
	if strings.Contains(err.Error(), private) {
		t.Fatal("ownership error exposed a configuration value")
	}
}

func configurationAsset(t *testing.T, v *bundle.Verified, id string, data []byte) {
	t.Helper()
	digest := spec.Hash(data)
	path := filepath.Join(v.Root, "blobs", "sha256", digest[7:])
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	asset := spec.LockedAsset{ID: id, Type: "file", Digest: digest, Size: int64(len(data)), Files: []spec.FileRecord{{Path: id, Digest: digest, Size: int64(len(data)), Mode: 0600}}}
	for i := range v.Index.Lock.Assets {
		if v.Index.Lock.Assets[i].ID == id {
			v.Index.Lock.Assets[i] = asset
			return
		}
	}
	v.Index.Lock.Assets = append(v.Index.Lock.Assets, asset)
}

func configurationChart(t *testing.T, v *bundle.Verified, defaults, schema string) {
	t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct{ name, body string }{
		{"Chart.yaml", "apiVersion: v2\nname: test\nversion: 1.0.0\nappVersion: 2.0.0\n"},
		{"values.yaml", defaults},
		{"values.schema.json", schema},
		{"templates/config.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: config\ndata:\n  resolved: {{ toJson .Values | quote }}\n"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: "test/" + entry.name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(entry.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	configurationAsset(t, v, "cinderlock-chart", data.Bytes())
}

func TestConfigurationPrecedenceReviewAndPinnedRevisionWithRealHelm(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("Helm executable unavailable; real schema/coalescing integration requires Helm")
	}
	e, _, _ := fixture(t)
	v := chartFixture(t, e)
	configurationChart(t, v, "auth:\n  token: vendor-private-token\n  realm: root-default\nnested:\n  left: default\n  right: original\nremove: default\narray: [default]\nreplicas: 1\nimage: upstream:1\n", `{"type":"object","properties":{"replicas":{"type":"integer","minimum":1,"maximum":2}}}`)
	configurationAsset(t, v, "cinderlock-values-0", []byte("auth:\n  realm: bundled\nnested: null\nremove: null\narray: [bundle]\n"))
	configurationAsset(t, v, "cinderlock-values-1", []byte("nested:\n  right: restored\n"))
	v.Index.Lock.Assets = append(v.Index.Lock.Assets, spec.LockedAsset{ID: "app", Type: "image", Digest: "sha256:" + strings.Repeat("e", 64)})
	deployment := &v.Index.Lock.Release.Spec.Deployment
	deployment.Values = []string{"first.yaml", "second.yaml"}
	deployment.ImageBindings = []spec.ImageBinding{{Asset: "app", ValuesPath: "image"}}
	deployment.Configuration = &spec.ConfigurationContract{Version: 1, Fields: []spec.ConfigurationField{
		{Path: "auth.token", Owner: "vendor", Type: "string", Required: true},
		{Path: "auth.realm", Owner: "site", Type: "string", Required: true},
		{Path: "nested", Owner: "vendor", Type: "object", Required: true},
		{Path: "remove", Owner: "vendor", Type: "string"},
		{Path: "array", Owner: "site", Type: "array", Required: true},
		{Path: "replicas", Owner: "site", Type: "integer", Required: true},
		{Path: "image", Owner: "generated", Type: "string", Required: true},
	}}
	e.Site.Spec.Values = map[string]any{"auth": map[string]any{"realm": "site-private-realm"}, "array": []any{"customer"}}
	prior := []byte(`{"auth":{"token":"vendor-private-token","realm":"prior-private-realm"},"nested":{"left":"default","right":"original"},"remove":"default","array":["default"],"replicas":1,"image":"prior-image"}`)
	priorAvailable := true
	latestRevision := 7
	e.HelmRunner = func(ctx context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "history":
			return json.Marshal([]map[string]any{{"revision": latestRevision, "status": "deployed", "app_version": "1.0.0"}})
		case "get":
			if pos := slices.Index(args, "--revision"); pos >= 0 {
				if args[pos+1] != "7" || !priorAvailable {
					return nil, errors.New("missing pinned revision")
				}
				return prior, nil
			}
			return []byte(`{"auth":{"realm":"latest-must-not-be-baseline"}}`), nil
		case "template":
			// Only Helm's local renderer runs here; cluster observations stay fake.
			return exec.CommandContext(ctx, helm, args...).CombinedOutput()
		}
		return nil, errors.New("unexpected test Helm operation")
	}
	chart, files, cleanup, err := e.helmFiles(v)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	resolved, err := resolveConfigurationFiles(chart, files, deployment.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := e.render(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	data := objects[0]["data"].(map[string]any)
	var actual map[string]any
	if err := spec.Decode([]byte(data["resolved"].(string)), &actual); err != nil {
		t.Fatal(err)
	}
	want, _ := spec.Canonical(resolved)
	got, _ := spec.Canonical(actual)
	if !bytes.Equal(want, got) || actual["nested"].(map[string]any)["left"] != "default" || actual["remove"] != nil || actual["auth"].(map[string]any)["realm"] != "site-private-realm" || !strings.Contains(actual["image"].(string), "@sha256:") {
		t.Fatal("resolved configuration differs from real Helm's ordered values/default coalescing")
	}
	if _, exists := e.Site.Spec.Values["image"]; exists {
		t.Fatal("generated image mutated customer Site values")
	}
	p := spec.Plan{Header: spec.NewHeader("Plan"), Snapshot: spec.TargetSnapshot{HelmRevision: 7, InstalledVersion: "1.0.0"}}
	review, err := e.configurationReview(context.Background(), p, v)
	if err != nil {
		t.Fatal(err)
	}
	if review.ComparisonRevision != 7 || review.ComparisonStatus != "available" || review.Ownership != "enforced" || !strings.HasPrefix(review.EffectiveDigest, "hmac-sha256:") {
		t.Fatal("review lacks its exact comparison scope and private effective configuration binding")
	}
	changes := map[string]string{}
	for _, field := range review.Fields {
		changes[field.Path] = field.Change
	}
	for path, expected := range map[string]string{"auth.token": "unchanged", "auth.realm": "changed", "nested": "changed", "remove": "removed", "array": "changed", "replicas": "unchanged", "image": "changed"} {
		if changes[path] != expected {
			t.Fatalf("incorrect masked change for %s", path)
		}
	}
	masked, _ := spec.Canonical(review)
	for _, private := range []string{"site-private-realm", "prior-private-realm", "vendor-private-token", spec.Hash([]byte("site-private-realm")), string(got)} {
		if bytes.Contains(masked, []byte(private)) {
			t.Fatal("review exposed a plaintext value, unkeyed value hash, or full configuration")
		}
	}
	p.ConfigurationReview = review
	latestRevision = 9 // Our deployment advanced Helm; the original review stays pinned.
	if err := e.checkConfigurationPlan(context.Background(), p, v); err != nil {
		t.Fatal("own Helm writes invalidated an unchanged pinned review:", err)
	}
	p.ConfigurationReview.Fields[0].Change = "not_compared"
	if err := e.checkConfigurationPlan(context.Background(), p, v); spec.ExitCode(err) != 11 {
		t.Fatal("modified masked metadata was accepted")
	}
	priorAvailable = false
	unavailable, err := e.configurationReview(context.Background(), p, v)
	if err == nil || unavailable.ComparisonStatus != "not_compared" {
		t.Fatal("missing original revision was replaced with a guessed baseline")
	}
	for _, field := range unavailable.Fields {
		if field.Change != "not_compared" {
			t.Fatal("missing original revision yielded an unjustified comparison")
		}
	}
	priorAvailable = true
	e.Site.Spec.Values["replicas"] = 3
	if _, err := e.render(context.Background(), v); err == nil {
		t.Fatal("Helm values.schema.json was bypassed for a basic-type-valid value")
	}
}

func TestConfigurationSiteOwnershipRejectsParentAndGeneratedBypass(t *testing.T) {
	for _, test := range []struct {
		name   string
		values map[string]any
	}{
		{"scalar-parent", map[string]any{"auth": "private-parent"}},
		{"null-parent", map[string]any{"auth": nil}},
		{"array-parent", map[string]any{"auth": []any{"private-parent"}}},
		{"generated-leaf", map[string]any{"runtime": map[string]any{"image": "private-registry/image:mutable"}}},
		{"generated-parent", map[string]any{"runtime": nil}},
		{"wrong-site-type", map[string]any{"auth": map[string]any{"realm": false}}},
		{"unknown-nested", map[string]any{"auth": map[string]any{"private-undeclared-key": "private-value"}}},
		{"dotted-alias", map[string]any{"auth.realm": "private-value"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, _, _ := fixture(t)
			v := chartFixture(t, e)
			v.Index.Lock.Assets = append(v.Index.Lock.Assets, spec.LockedAsset{ID: "app", Type: "image", Digest: "sha256:" + strings.Repeat("a", 64)})
			deployment := &v.Index.Lock.Release.Spec.Deployment
			deployment.ImageBindings = []spec.ImageBinding{{Asset: "app", ValuesPath: "runtime.image"}}
			deployment.Configuration = &spec.ConfigurationContract{Version: 1, Fields: []spec.ConfigurationField{
				{Path: "auth.token", Owner: "vendor", Type: "string"},
				{Path: "auth.realm", Owner: "site", Type: "string"},
				{Path: "runtime.image", Owner: "generated", Type: "string", Required: true},
			}}
			e.Site.Spec.Values = test.values
			_, _, cleanup, err := e.helmFiles(v)
			if cleanup != nil {
				cleanup()
			}
			if err == nil || strings.Contains(err.Error(), "private-") {
				t.Fatal("override must be rejected without exposing supplied values or undeclared keys")
			}
		})
	}
}

func TestConfigurationRenderFailureDoesNotExposeValues(t *testing.T) {
	e, _, _ := fixture(t)
	v := chartFixture(t, e)
	const private = "schema-error-private-value"
	e.HelmRunner = func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "history" {
			return []byte(`[{"revision":1,"status":"deployed","app_version":"1.0.0"}]`), nil
		}
		if args[0] == "get" {
			return []byte(`{}`), nil
		}
		return nil, errors.New("template rejected value " + private)
	}
	_, err := e.render(context.Background(), v)
	if err == nil || strings.Contains(err.Error(), private) {
		t.Fatal("render failure must remain an error without exposing rejected configuration values")
	}
}

func TestConfigurationRequiredTypesAndAtomicObjectScope(t *testing.T) {
	for _, test := range []struct {
		name     string
		kind     string
		required bool
		value    any
		accepted bool
	}{
		{"required-null", "string", true, nil, false},
		{"optional-null", "string", false, nil, true},
		{"wrong-string", "string", true, false, false},
		{"safe-integer", "integer", true, 2, true},
		{"string-integer", "integer", true, "2", false},
		{"fraction", "integer", true, 1.5, false},
		{"unsafe-integer", "integer", true, uint64(9007199254740992), false},
		{"boolean", "boolean", true, true, true},
		{"array", "array", true, []any{"endpoint"}, true},
		{"wrong-array", "array", true, map[string]any{}, false},
		{"atomic-object", "object", true, map[string]any{"nested": map[string]any{"private-key": "value"}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, _, _ := fixture(t)
			v := chartFixture(t, e)
			v.Index.Lock.Release.Spec.Deployment.Configuration = &spec.ConfigurationContract{Version: 1, Fields: []spec.ConfigurationField{{Path: "setting", Owner: "site", Type: test.kind, Required: test.required}}}
			e.Site.Spec.Values = map[string]any{"setting": test.value}
			_, _, cleanup, err := e.helmFiles(v)
			if cleanup != nil {
				cleanup()
			}
			if (err == nil) != test.accepted {
				t.Fatalf("incorrect required/type admission: accepted=%v", err == nil)
			}
		})
	}
	e, _, _ := fixture(t)
	v := chartFixture(t, e)
	v.Index.Lock.Release.Spec.Deployment.Configuration = &spec.ConfigurationContract{Version: 1, Fields: []spec.ConfigurationField{{Path: "absent", Owner: "vendor", Type: "string", Required: true}}}
	if _, _, cleanup, err := e.helmFiles(v); err == nil {
		cleanup()
		t.Fatal("missing required bundled/default value was accepted")
	}
}

func TestConfigurationPlanReviewAdmissionAndLegacyScope(t *testing.T) {
	e, _, policy := fixture(t)
	_, v := fixturePlan(t, e, policy)
	chart := chartFixture(t, e)
	v.Root = chart.Root
	v.Index.Lock.Assets = append(v.Index.Lock.Assets, chart.Index.Lock.Assets...)
	e.HelmRunner = func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "history":
			return []byte(`[{"revision":1,"status":"deployed","app_version":"1.0.0"}]`), nil
		case "get":
			return []byte(`{"setting":"default"}`), nil
		case "template":
			return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fixed\ndata:\n  setting: fixed\n"), nil
		}
		return nil, errors.New("unexpected fixture Helm request")
	}
	sitePath := filepath.Join(e.StateDir, "site.json")
	legacy, err := e.Plan(context.Background(), v, "bundle.cinder", sitePath, policy)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.ConfigurationReview == nil || legacy.ConfigurationReview.Ownership != "unqualified" || legacy.ConfigurationReview.EffectiveDigest != "" || len(legacy.ConfigurationReview.Fields) != 0 {
		t.Fatal("legacy release received an implicit ownership qualification")
	}
	v.Index.Lock.Release.Spec.Deployment.Configuration = &spec.ConfigurationContract{Version: 1, Fields: []spec.ConfigurationField{{Path: "setting", Owner: "site", Type: "string", Required: true}}}
	e.Site.Spec.Values = map[string]any{"setting": "unused-private-value"}
	body, err := spec.Canonical(e.Site)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sitePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	planned, err := e.Plan(context.Background(), v, "bundle.cinder", sitePath, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !planned.Executable || planned.ConfigurationReview.Ownership != "enforced" || planned.ConfigurationReview.Fields[0].Change != "changed" {
		t.Fatalf("plan did not expose the enforced masked review: executable=%v findings=%v", planned.Executable, planned.Findings)
	}
	if err := e.checkPlan(context.Background(), planned, v, policy, false); err != nil {
		t.Fatal(err)
	}
	planned.ConfigurationReview.Fields[0].Owner = "vendor"
	if err := e.checkPlan(context.Background(), planned, v, policy, false); spec.ExitCode(err) != 11 {
		t.Fatal("execution boundary accepted a fabricated ownership review")
	}
	planned.ConfigurationReview.Fields[0].Owner = "site"
	e.Site.Spec.Values["setting"] = "different-unused-private-value"
	if err := e.checkConfigurationPlan(context.Background(), planned, v); spec.ExitCode(err) != 11 {
		t.Fatal("changed effective values escaped the keyed configuration binding when rendered resources stayed fixed")
	}
	install := spec.Plan{Header: spec.NewHeader("Plan"), Snapshot: spec.TargetSnapshot{Facts: []spec.Fact{{Name: "helm.release", Status: "absent", Source: "confirmed Helm history absence"}}}}
	review, err := e.configurationReview(context.Background(), install, v)
	if err != nil || review.ComparisonStatus != "not_installed" || review.Fields[0].Change != "added" {
		t.Fatal("fresh installation did not explicitly identify its empty comparison baseline")
	}
}

func TestConfigurationFailedHelmObservationCannotBecomeInstallationBaseline(t *testing.T) {
	for _, failure := range []struct {
		name string
		err  error
	}{
		{"history-unavailable", errors.New("PRIVATE-HISTORY-FAILURE")},
		{"storage-api-absent", apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "history")},
		{"skipped", nil},
	} {
		t.Run(failure.name, func(t *testing.T) {
			e, _, _ := fixture(t)
			v := chartFixture(t, e)
			v.Index.Lock.Release.Spec.Deployment.Configuration = &spec.ConfigurationContract{Version: 1, Fields: []spec.ConfigurationField{{Path: "setting", Owner: "site", Type: "string"}}}
			snapshot := spec.TargetSnapshot{}
			if failure.err != nil {
				e.HelmRunner = func(context.Context, ...string) ([]byte, error) { return nil, failure.err }
				var err error
				snapshot, err = e.Inspect(context.Background())
				if err != nil {
					t.Fatal(err)
				}
			}
			review, err := e.configurationReview(context.Background(), spec.Plan{Snapshot: snapshot}, v)
			if err == nil || review.ComparisonStatus != "not_compared" {
				t.Fatalf("failed release read became installation baseline: status=%s err=%v", review.ComparisonStatus, err)
			}
			if len(review.Fields) != 1 || review.Fields[0].Change != "not_compared" {
				t.Fatalf("failed read yielded a guessed field comparison: %+v", review.Fields)
			}
		})
	}
}
