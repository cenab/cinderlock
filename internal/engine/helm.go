package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"gopkg.in/yaml.v3"
)

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("subprocess output exceeds limit")
	}
	return b.Buffer.Write(p)
}

func (e *Engine) helm(ctx context.Context, args ...string) ([]byte, error) {
	if e.HelmRunner != nil {
		return e.HelmRunner(ctx, args...)
	}
	path := e.Site.Spec.HelmPath
	if path == "" || e.Site.Spec.HelmDigest == "" {
		return nil, spec.Err(10, "site must pin Helm executable path and SHA-256 digest")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != e.Site.Spec.HelmDigest {
		return nil, spec.Err(12, "Helm executable digest does not match admitted site toolchain")
	}
	work, err := os.MkdirTemp(e.StateDir, "helm-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	if err := os.Mkdir(filepath.Join(work, "plugins"), 0700); err != nil {
		return nil, err
	}
	kubeconfig, err := e.Kube.writeConfigSnapshot(work)
	if err != nil {
		return nil, err
	}
	args = append(args, "--kubeconfig", kubeconfig, "--kube-context", e.Kube.Context, "--namespace", e.Kube.Namespace)
	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Dir = work
	cmd.Env = []string{"PATH=" + filepath.Dir(resolved), "HOME=" + work, "KUBECONFIG=" + kubeconfig, "HELM_CACHE_HOME=" + work, "HELM_CONFIG_HOME=" + work, "HELM_DATA_HOME=" + work, "HELM_PLUGINS=" + filepath.Join(work, "plugins"), "LANG=C", "LC_ALL=C"}
	out := &limitedBuffer{limit: 16 << 20}
	stderr := &limitedBuffer{limit: 1 << 20}
	cmd.Stdout = out
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("Helm operation failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), nil
}

type helmHistoryEntry struct {
	Revision   int64  `json:"revision"`
	Status     string `json:"status"`
	AppVersion string `json:"app_version"`
}

func (e *Engine) helmHistory(ctx context.Context) (helmHistoryEntry, bool, error) {
	b, err := e.helm(ctx, "history", e.Site.Spec.ReleaseName, "--output", "json")
	if err != nil {
		if strings.Contains(err.Error(), "release: not found") || strings.Contains(err.Error(), "release not found") {
			return helmHistoryEntry{}, true, nil
		}
		return helmHistoryEntry{}, false, err
	}
	var rows []helmHistoryEntry
	if err := json.Unmarshal(b, &rows); err != nil {
		return helmHistoryEntry{}, false, err
	}
	if len(rows) == 0 {
		return helmHistoryEntry{}, false, errors.New("Helm history is empty but release was not absent")
	}
	return rows[len(rows)-1], false, nil
}

func (e *Engine) helmState(ctx context.Context) (revision int64, version string, values []byte, err error) {
	latest, absent, err := e.helmHistory(ctx)
	if err != nil {
		return 0, "", nil, err
	}
	if absent {
		return 0, "", []byte(`{}`), nil
	}
	if latest.Status == "uninstalled" {
		return latest.Revision, "", []byte(`{}`), nil
	}
	if strings.HasPrefix(latest.Status, "pending-") {
		return 0, "", nil, spec.Err(13, "Helm release has an uncertain pending operation")
	}
	if latest.Status != "deployed" && latest.Status != "failed" {
		return 0, "", nil, spec.Err(10, "unsupported Helm release state %q", latest.Status)
	}
	values, err = e.helm(ctx, "get", "values", e.Site.Spec.ReleaseName, "--all", "--output", "json")
	return latest.Revision, latest.AppVersion, values, err
}

func (e *Engine) helmFiles(v *bundle.Verified) (string, []string, func(), error) {
	deployment := v.Index.Lock.Release.Spec.Deployment
	if err := spec.ValidateConfigurationContract(deployment); err != nil {
		return "", nil, nil, err
	}
	if deployment.Configuration != nil {
		if err := checkSiteConfiguration(deployment.Configuration, e.Site.Spec.Values); err != nil {
			return "", nil, nil, err
		}
	}
	dir, err := os.MkdirTemp(e.StateDir, "chart-")
	if err != nil {
		return "", nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	chart, err := bundle.Materialize(v, "cinderlock-chart", filepath.Join(dir, "chart"))
	if err != nil {
		cleanup()
		return "", nil, nil, err
	}
	metadata, _, err := chartSource(chart, v.Index.Lock.Release.Metadata.Version)
	if err != nil {
		cleanup()
		return "", nil, nil, err
	}
	if err := inspectChart(chart, metadata["name"].(string)); err != nil {
		cleanup()
		return "", nil, nil, err
	}
	values := []string{}
	for i := range v.Index.Lock.Release.Spec.Deployment.Values {
		p, err := bundle.Materialize(v, fmt.Sprintf("cinderlock-values-%d", i), filepath.Join(dir, fmt.Sprintf("values-%d", i)))
		if err != nil {
			cleanup()
			return "", nil, nil, err
		}
		values = append(values, p)
	}
	resolvedValues := map[string]any{}
	if len(e.Site.Spec.Values) > 0 {
		b, err := json.Marshal(e.Site.Spec.Values)
		if err != nil {
			cleanup()
			return "", nil, nil, err
		}
		if err := json.Unmarshal(b, &resolvedValues); err != nil {
			cleanup()
			return "", nil, nil, err
		}
	}
	for _, binding := range v.Index.Lock.Release.Spec.Deployment.ImageBindings {
		image, err := e.image(v, binding.Asset)
		if err != nil {
			cleanup()
			return "", nil, nil, err
		}
		if err := setValuePath(resolvedValues, binding.ValuesPath, image); err != nil {
			cleanup()
			return "", nil, nil, err
		}
	}
	if len(resolvedValues) > 0 {
		p := filepath.Join(dir, "site-values.json")
		if err := spec.Write(p, resolvedValues); err != nil {
			cleanup()
			return "", nil, nil, err
		}
		values = append(values, p)
	}
	if deployment.Configuration != nil {
		if _, err := resolveConfigurationFiles(chart, values, deployment.Configuration); err != nil {
			cleanup()
			return "", nil, nil, err
		}
	}
	return chart, values, cleanup, nil
}

func setValuePath(values map[string]any, path, value string) error {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return errors.New("empty image value path")
	}
	current := values
	for i, part := range parts {
		if part == "" || strings.ContainsAny(part, "[]\\") {
			return errors.New("only explicit dotted object image bindings are supported")
		}
		if i == len(parts)-1 {
			current[part] = value
			return nil
		}
		next, ok := current[part]
		if !ok {
			child := map[string]any{}
			current[part] = child
			current = child
			continue
		}
		child, ok := next.(map[string]any)
		if !ok {
			return errors.New("image binding conflicts with a non-object value")
		}
		current = child
	}
	return nil
}

func inspectChart(path, chartName string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("chart must be packaged tgz: %w", err)
	}
	defer gz.Close()
	stream := &io.LimitedReader{R: gz, N: 64<<20 + 1}
	tr := tar.NewReader(stream)
	for {
		h, err := tr.Next()
		if stream.N == 0 {
			return spec.Err(10, "chart exceeds supported uncompressed size")
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if !spec.SafePath(strings.TrimSuffix(h.Name, "/")) {
			return spec.Err(10, "chart archive paths must be canonical forward-slash paths")
		}
		if h.Size > 4<<20 {
			return errors.New("chart member exceeds limit")
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return errors.New("chart links and special files unsupported")
		}
		b, err := io.ReadAll(io.LimitReader(tr, 4<<20+1))
		if err != nil {
			return err
		}
		if stream.N == 0 || int64(len(b)) != h.Size {
			return spec.Err(10, "chart exceeds supported size or contains a truncated member")
		}
		_, member, _ := strings.Cut(h.Name, "/")
		if strings.HasPrefix(member, "charts/") {
			return spec.Err(10, "bundled subcharts require another supported template-inspection profile")
		}
		if strings.HasPrefix(member, "templates/") {
			if err := inspectChartTemplate(chartName+"/"+member, string(b)); err != nil {
				return err
			}
		}
	}
}

type helmRenderContext struct{ IsUpgrade bool }

func (e *Engine) render(ctx context.Context, v *bundle.Verified) ([]map[string]any, error) {
	_, installed, _, err := e.helmState(ctx)
	if err != nil {
		return nil, err
	}
	return e.renderWithContext(ctx, v, helmRenderContext{IsUpgrade: installed != ""})
}

func (e *Engine) renderWithContext(ctx context.Context, v *bundle.Verified, frame helmRenderContext) ([]map[string]any, error) {
	chart, values, cleanup, err := e.helmFiles(v)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	args := []string{"template", e.Site.Spec.ReleaseName, chart, "--include-crds"}
	if frame.IsUpgrade {
		args = append(args, "--is-upgrade")
	}
	for _, p := range values {
		args = append(args, "--values", p)
	}
	b, err := e.helm(ctx, args...)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Schema/template failures can echo supplied values. The plan and its
		// findings must not become a second secret store through Helm stderr.
		return nil, spec.Err(10, "Helm configuration schema or template validation failed; rejected values are withheld")
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	objects := []map[string]any{}
	allowed := map[string]bool{"Deployment": true, "StatefulSet": true, "Service": true, "ConfigMap": true, "Secret": true, "PersistentVolumeClaim": true, "ServiceAccount": true, "Role": true, "RoleBinding": true, "NetworkPolicy": true, "PodDisruptionBudget": true}
	for {
		var o map[string]any
		err := dec.Decode(&o)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(o) == 0 {
			continue
		}
		kind, _ := o["kind"].(string)
		if !allowed[kind] {
			return nil, spec.Err(10, "chart kind %q unsupported in namespaced profile", kind)
		}
		m, _ := o["metadata"].(map[string]any)
		if ns, _ := m["namespace"].(string); ns != "" && ns != e.Site.Spec.Namespace {
			return nil, spec.Err(16, "chart changes another namespace")
		}
		if a, _ := m["annotations"].(map[string]any); a["helm.sh/hook"] != nil {
			return nil, spec.Err(10, "chart hooks unsupported in first execution profile")
		}
		objects = append(objects, o)
		if err := e.inspectRenderedImages(o, v); err != nil {
			return nil, err
		}
	}
	if len(objects) == 0 {
		return nil, spec.Err(10, "chart renders no supported resources")
	}
	if err := e.inspectGPUWorkloads(ctx, objects, v); err != nil {
		return nil, err
	}
	return objects, nil
}

// RenderDesiredState creates reviewed controller input without writing to Kubernetes or a Git remote.
func (e *Engine) RenderDesiredState(ctx context.Context, v *bundle.Verified) ([]byte, error) {
	objects, err := e.render(ctx, v)
	if err != nil {
		return nil, err
	}
	return encodeObjects(objects)
}

func encodeObjects(objects []map[string]any) ([]byte, error) {
	var b bytes.Buffer
	encoder := yaml.NewEncoder(&b)
	encoder.SetIndent(2)
	for _, object := range objects {
		if err := encoder.Encode(object); err != nil {
			return nil, err
		}
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (e *Engine) Image(v *bundle.Verified, reference string) (string, error) {
	return e.image(v, reference)
}

func (e *Engine) inspectRenderedImages(object map[string]any, v *bundle.Verified) error {
	allowed := map[string]bool{}
	for _, asset := range v.Index.Lock.Assets {
		if asset.Type == "image" {
			image, err := e.image(v, asset.ID)
			if err != nil {
				return err
			}
			allowed[image] = true
		}
	}
	var walk func(any) error
	walk = func(value any) error {
		switch node := value.(type) {
		case map[string]any:
			for key, value := range node {
				if key == "containers" || key == "initContainers" || key == "ephemeralContainers" {
					containers, ok := value.([]any)
					if !ok {
						return errors.New("rendered containers field is invalid")
					}
					for _, entry := range containers {
						container, ok := entry.(map[string]any)
						if !ok {
							return errors.New("rendered container is invalid")
						}
						image, _ := container["image"].(string)
						if !allowed[image] {
							return spec.Err(10, "rendered image is not an imported digest-pinned release asset: %s", image)
						}
					}
				}
				if err := walk(value); err != nil {
					return err
				}
			}
		case []any:
			for _, value := range node {
				if err := walk(value); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(object)
}

func (e *Engine) deploy(ctx context.Context, plan spec.Plan, v *bundle.Verified) error {
	objects, err := e.render(ctx, v)
	if err != nil {
		return err
	}
	digest, err := spec.Digest(objects)
	if err != nil {
		return err
	}
	if plan.DesiredStateDigest == "" || digest != plan.DesiredStateDigest {
		return spec.Err(11, "rendered resources differ from the reviewed desired state")
	}
	chart, values, cleanup, err := e.helmFiles(v)
	if err != nil {
		return err
	}
	defer cleanup()
	frozen, err := freezeChart(chart, filepath.Join(filepath.Dir(chart), "frozen"), objects, v.Index.Lock.Release.Metadata.Version)
	if err != nil {
		return err
	}
	verb := "upgrade"
	if plan.SourceVersion == "" {
		verb = "install"
	}
	args := []string{verb, e.Site.Spec.ReleaseName, frozen, "--wait", "--timeout", "5m"}
	for _, p := range values {
		args = append(args, "--values", p)
	}
	_, err = e.helm(ctx, args...)
	return err
}

// Freeze the checked resources so Helm cannot execute source templates again.
func freezeChart(source, destination string, objects []map[string]any, version string) (string, error) {
	metadata, defaults, err := chartSource(source, version)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(filepath.Join(destination, "templates"), 0700); err != nil {
		return "", err
	}
	if err = os.Mkdir(filepath.Join(destination, "files"), 0700); err != nil {
		return "", err
	}
	data, err := encodeObjects(objects)
	if err != nil {
		return "", err
	}
	info, err := yaml.Marshal(map[string]any{"apiVersion": "v2", "type": "application", "name": metadata["name"], "version": metadata["version"], "appVersion": metadata["appVersion"], "description": "Frozen validated Cinderlock release resources"})
	if err != nil {
		return "", err
	}
	for _, entry := range []struct {
		name string
		data []byte
	}{{"Chart.yaml", info}, {"values.yaml", defaults}, {"templates/resources.yaml", []byte("{{ .Files.Get \"files/resources.yaml\" }}\n")}, {"files/resources.yaml", data}} {
		if err = spec.WriteBytes(filepath.Join(destination, entry.name), entry.data); err != nil {
			return "", err
		}
	}
	return destination, nil
}

func chartSource(source, version string) (map[string]any, []byte, error) {
	f, err := os.Open(source)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, 64<<20))
	var metadata map[string]any
	var defaults []byte
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		parts := strings.Split(h.Name, "/")
		if h.Typeflag != tar.TypeReg || len(parts) != 2 {
			continue
		}
		if parts[1] != "Chart.yaml" && parts[1] != "values.yaml" {
			continue
		}
		if h.Size > 4<<20 {
			return nil, nil, spec.Err(10, "chart metadata/defaults exceeds supported profile")
		}
		b, err := io.ReadAll(io.LimitReader(tr, 4<<20+1))
		if err != nil {
			return nil, nil, err
		}
		if parts[1] == "values.yaml" {
			defaults = b
			continue
		}
		if metadata != nil {
			return nil, nil, spec.Err(12, "multiple chart metadata entries")
		}
		if err = spec.Decode(b, &metadata); err != nil {
			return nil, nil, err
		}
	}
	chartName, _ := metadata["name"].(string)
	chartVersion, _ := metadata["version"].(string)
	appVersion, _ := metadata["appVersion"].(string)
	if chartName == "" || chartVersion == "" || appVersion != version {
		return nil, nil, spec.Err(10, "chart must name a version and appVersion matching the declared release")
	}
	return metadata, defaults, nil
}
