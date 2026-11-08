package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestInspectionSecretFingerprints(t *testing.T) {
	for _, scope := range []struct {
		name     string
		managed  bool
		selected bool
		whole    bool
		pull     bool
	}{
		{name: "selected-keys", selected: true},
		{name: "selected-keys-in-inventory", selected: true, managed: true},
		{name: "whole-secret", selected: true, whole: true},
		{name: "whole-secret-in-inventory", selected: true, whole: true, managed: true},
		{name: "image-pull", pull: true},
		{name: "image-pull-with-selected-keys-in-inventory", selected: true, pull: true, managed: true},
		{name: "unreferenced-inventory", managed: true},
	} {
		t.Run(scope.name, func(t *testing.T) {
			e, client, _ := fixture(t)
			ctx := context.Background()
			e.Site.Spec.SecretRefs = map[string]spec.SecretRef{}
			if scope.selected {
				e.Site.Spec.SecretRefs["api-token"] = spec.SecretRef{Name: "credentials", Key: "token"}
				e.Site.Spec.SecretRefs["password"] = spec.SecretRef{Namespace: "test", Name: "credentials", Key: "password"}
			}
			if scope.whole {
				e.Site.Spec.SecretRefs["whole"] = spec.SecretRef{Name: "credentials"}
			}
			if scope.pull {
				e.Site.Spec.ImagePullSecrets = []string{"credentials"}
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "credentials", Namespace: "test", UID: "secret-uid", ResourceVersion: "1",
					Labels: map[string]string{}, Annotations: map[string]string{},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"token": []byte("inspection-private-token"), "password": []byte("inspection-private-password"),
					"unrelated": []byte("inspection-private-unrelated"),
				},
			}
			if scope.managed {
				secret.Labels["app.kubernetes.io/instance"] = "app"
				secret.Annotations["meta.helm.sh/release-name"] = "app"
			}
			if scope.pull {
				secret.Type = corev1.SecretTypeDockerConfigJson
				secret.Data[corev1.DockerConfigJsonKey] = []byte(`{"auths":{"registry.internal":{"username":"operator","password":"inspection-private-registry"}}}`)
			}
			if _, err := client.CoreV1().Secrets("test").Create(ctx, secret, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			inspect := func(t *testing.T, current *corev1.Secret) string {
				t.Helper()
				client.ClearActions()
				snapshot, err := e.Inspect(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, action := range client.Actions() {
					if action.GetVerb() != "get" && action.GetVerb() != "list" {
						t.Fatalf("inspection mutated cluster: %s", action.GetVerb())
					}
				}
				for _, resource := range snapshot.Resources {
					if resource.Kind == "Secret" && !strings.HasPrefix(resource.Fingerprint, "hmac-sha256:") {
						t.Fatal("Secret inventory lacks a private fingerprint")
					}
				}
				facts := map[string]spec.Fact{}
				for _, fact := range snapshot.Facts {
					facts[fact.Name] = fact
					if strings.HasPrefix(fact.Name, "secret/") && fact.Status == "known" && !strings.HasPrefix(fact.Value, "hmac-sha256:") {
						t.Fatal("Secret reference lacks a private fingerprint")
					}
				}
				for name, ref := range e.Site.Spec.SecretRefs {
					want := "known"
					if _, ok := current.Data[ref.Key]; ref.Key != "" && !ok {
						want = "absent"
					}
					if facts["secret/"+name].Status != want {
						t.Fatalf("Secret reference %s status = %s, want %s", name, facts["secret/"+name].Status, want)
					}
				}
				for _, name := range e.Site.Spec.ImagePullSecrets {
					if facts["secret/image-pull-"+name].Status != "known" {
						t.Fatal("image-pull Secret reference is unavailable")
					}
				}
				values := [][]byte{}
				for _, data := range []map[string][]byte{secret.Data, current.Data} {
					for _, value := range data {
						values = append(values, value)
					}
					body, err := json.Marshal(data)
					if err != nil {
						t.Fatal(err)
					}
					values = append(values, body)
				}
				assertInspectionPrivate(t, snapshot, values...)
				digest, err := snapshotDigest(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				return digest
			}
			want := inspect(t, secret)
			full := scope.managed || scope.whole || scope.pull || !scope.selected
			for _, change := range []struct {
				name       string
				mutate     func(*corev1.Secret)
				wantChange bool
			}{
				{"labels", func(s *corev1.Secret) { s.Labels["rotation"] = "observed" }, false},
				{"annotations", func(s *corev1.Secret) { s.Annotations["rotation"] = "observed" }, false},
				{"resource-version", func(s *corev1.Secret) { s.ResourceVersion = "2" }, false},
				{"selected-data", func(s *corev1.Secret) { s.Data["token"] = []byte("inspection-private-rotated-token") }, true},
				{"second-selected-key", func(s *corev1.Secret) { s.Data["password"] = []byte("inspection-private-rotated-password") }, true},
				{"unrelated-data", func(s *corev1.Secret) { s.Data["unrelated"] = []byte("inspection-private-rotated-unrelated") }, full},
				{"added-key", func(s *corev1.Secret) { s.Data["extra"] = []byte("inspection-private-extra") }, full},
				{"removed-unrelated-key", func(s *corev1.Secret) { delete(s.Data, "unrelated") }, full},
				{"removed-selected-key", func(s *corev1.Secret) { delete(s.Data, "token") }, true},
				{"type", func(s *corev1.Secret) { s.Type = corev1.SecretTypeTLS }, true},
				{"uid-replacement", func(s *corev1.Secret) { s.UID = "replacement-uid" }, true},
			} {
				t.Run(change.name, func(t *testing.T) {
					current := secret.DeepCopy()
					change.mutate(current)
					if change.name == "uid-replacement" {
						if err := client.CoreV1().Secrets("test").Delete(ctx, secret.Name, metav1.DeleteOptions{}); err != nil {
							t.Fatal(err)
						}
						if _, err := client.CoreV1().Secrets("test").Create(ctx, current, metav1.CreateOptions{}); err != nil {
							t.Fatal(err)
						}
					} else if _, err := client.CoreV1().Secrets("test").Update(ctx, current, metav1.UpdateOptions{}); err != nil {
						t.Fatal(err)
					}
					got := inspect(t, current)
					if (got != want) != change.wantChange {
						t.Fatalf("snapshot drift = %t, want %t", got != want, change.wantChange)
					}
				})
			}
		})
	}
}

func TestInspectionSecretFileFingerprints(t *testing.T) {
	e, _, _ := fixture(t)
	path := filepath.Join(e.StateDir, "private-file-sentinel")
	e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"registry": {File: path}}
	original, rotated := []byte("inspection-private-file-one"), []byte("inspection-private-file-two")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	inspect := func() string {
		t.Helper()
		snapshot, err := e.Inspect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		known := false
		for _, fact := range snapshot.Facts {
			if fact.Name == "secret/registry" {
				known = fact.Status == "known" && strings.HasPrefix(fact.Value, "hmac-sha256:")
			}
		}
		if !known {
			t.Fatal("private file reference lacks a private fingerprint")
		}
		assertInspectionPrivate(t, snapshot, original, rotated, []byte(path))
		digest, err := snapshotDigest(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	want := inspect()
	touched := info.ModTime().Add(time.Hour)
	if err := os.Chtimes(path, touched, touched); err != nil {
		t.Fatal(err)
	}
	if inspect() != want {
		t.Fatal("private file mtime update changed inspected snapshot digest")
	}
	if err := os.WriteFile(path, rotated, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		t.Fatal("test failed to preserve file size and mtime")
	}
	if inspect() == want {
		t.Fatal("private file byte change with unchanged metadata did not invalidate snapshot")
	}
}

func TestInspectionSecretFileBoundaries(t *testing.T) {
	for _, kind := range []string{"missing", "public", "directory", "symlink", "fifo", "oversized", "limit"} {
		t.Run(kind, func(t *testing.T) {
			e, _, _ := fixture(t)
			path := filepath.Join(e.StateDir, "private-file-path-sentinel")
			e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"registry": {File: path}}
			const private = "inspection-private-file-content"
			var err error
			switch kind {
			case "public":
				err = os.WriteFile(path, []byte(private), 0644)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink":
				target := filepath.Join(e.StateDir, "target")
				if err := os.WriteFile(target, []byte(private), 0600); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(target, path)
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			case "oversized", "limit":
				size := 1 << 20
				if kind == "oversized" {
					size++
				}
				err = os.WriteFile(path, bytes.Repeat([]byte{'x'}, size), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := e.Inspect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			assertInspectionPrivate(t, snapshot, []byte(path), []byte(private))
			want := "unavailable"
			if kind == "missing" {
				want = "absent"
			}
			if kind == "limit" {
				want = "known"
			}
			for _, fact := range snapshot.Facts {
				if fact.Name == "secret/registry" {
					if fact.Status != want || want != "known" && fact.Value != "" {
						t.Fatalf("file reference status = %s, want %s with no unavailable value", fact.Status, want)
					}
					return
				}
			}
			t.Fatal("file reference fact missing")
		})
	}
}

func TestInspectionSecretAccessErrorsStayPrivate(t *testing.T) {
	for _, verb := range []string{"get", "list"} {
		t.Run(verb, func(t *testing.T) {
			e, client, _ := fixture(t)
			e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"api-token": {Name: "credentials", Key: "token"}}
			const private = "inspection-private-api-error"
			client.PrependReactor(verb, "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New(private)
			})
			snapshot, err := e.Inspect(context.Background())
			if err != nil && strings.Contains(err.Error(), private) {
				t.Fatal("Secret access error disclosed private error text")
			}
			assertInspectionPrivate(t, snapshot, []byte(private))
			if verb == "list" {
				if err != nil {
					t.Fatal(err)
				}
				if targetObservationError(snapshot) == nil {
					t.Fatal("failed Secret inventory did not block")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, fact := range snapshot.Facts {
				if fact.Name == "secret/api-token" && fact.Status == "unavailable" && fact.Value == "" {
					return
				}
			}
			t.Fatal("denied Secret reference was not unavailable")
		})
	}
}

func TestInspectionSecretOwnerAndNamespaceGuards(t *testing.T) {
	for _, conflict := range []string{"helm-owner", "gitops-owner", "namespace"} {
		t.Run(conflict, func(t *testing.T) {
			e, client, _ := fixture(t)
			ctx := context.Background()
			e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"api-token": {Name: "credentials", Key: "token"}}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Name: "credentials", Namespace: "test", UID: "secret-uid",
				Labels: map[string]string{"app.kubernetes.io/instance": "app"},
			}, Data: map[string][]byte{"token": []byte("inspection-private-owned-token")}}
			switch conflict {
			case "helm-owner":
				secret.Annotations = map[string]string{"meta.helm.sh/release-name": "other"}
			case "gitops-owner":
				secret.Labels["argocd.argoproj.io/instance"] = "other"
			case "namespace":
				e.Site.Spec.SecretRefs["api-token"] = spec.SecretRef{Namespace: "other", Name: "credentials", Key: "token"}
			}
			if _, err := client.CoreV1().Secrets("test").Create(ctx, secret, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			client.ClearActions()
			snapshot, err := e.Inspect(ctx)
			if err == nil {
				t.Fatal("Secret ownership or namespace conflict was accepted")
			}
			assertInspectionPrivate(t, snapshot, secret.Data["token"])
			if strings.Contains(err.Error(), string(secret.Data["token"])) {
				t.Fatal("Secret guard error disclosed private bytes")
			}
			if conflict == "namespace" {
				if spec.ExitCode(err) != 16 {
					t.Fatalf("cross-namespace reference exit code = %d, want 16", spec.ExitCode(err))
				}
				for _, action := range client.Actions() {
					if action.GetNamespace() == "other" {
						t.Fatal("inspection accessed a cross-namespace reference")
					}
				}
			}
		})
	}
}

func assertInspectionPrivate(t *testing.T, snapshot spec.TargetSnapshot, values ...[]byte) {
	t.Helper()
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		for _, disclosed := range []string{string(value), base64.StdEncoding.EncodeToString(value), spec.Hash(value), strings.TrimPrefix(spec.Hash(value), "sha256:")} {
			if bytes.Contains(body, []byte(disclosed)) {
				t.Fatal("inspection disclosed private bytes or a plain secret hash")
			}
		}
	}
}

func TestInspectionRejectsAmbiguousSecretFactNames(t *testing.T) {
	e, _, _ := fixture(t)
	e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"image-pull-credentials": {Name: "credentials", Key: "missing"}}
	e.Site.Spec.ImagePullSecrets = []string{"credentials"}
	if _, err := e.Inspect(context.Background()); spec.ExitCode(err) != 16 {
		t.Fatalf("ambiguous Secret fact names accepted: %v", err)
	}
}
