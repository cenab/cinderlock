package transfer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func deltaFixture(t *testing.T) (*bundle.Verified, *bundle.Verified, spec.TrustPolicy) {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "key.pem")
	if err := bundle.GenerateKey(key, filepath.Join(dir, "public.pem")); err != nil {
		t.Fatal(err)
	}
	priv, err := bundle.ReadPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	policy := spec.TrustPolicy{Header: spec.NewHeader("TrustPolicy"), Spec: spec.TrustSpec{Epoch: 1, Keys: []spec.TrustedKey{{ID: "release", PublicKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)), Applications: []string{"demo"}, Channels: []string{"stable"}, Roles: []string{"release"}}}}}
	if err := os.WriteFile(filepath.Join(dir, "chart.tgz"), []byte("shared chart transport"), 0600); err != nil {
		t.Fatal(err)
	}
	var versions []*bundle.Verified
	for n, version := range []string{"1", "2"} {
		modelName := "model-" + version
		if err := os.WriteFile(filepath.Join(dir, modelName), []byte("model "+version), 0600); err != nil {
			t.Fatal(err)
		}
		r := spec.Release{Header: spec.NewHeader("Release"), Spec: spec.ReleaseSpec{Profile: "lab", Deployment: spec.Deployment{Type: "helm", Chart: "chart.tgz"}, Assets: []spec.Asset{{ID: "model", Type: "file", Source: modelName}}, Operations: []spec.Operation{{ID: "deploy", Type: "helm", Idempotent: true}}, Checks: []spec.Check{{ID: "health", Type: "http", Domain: "workflow", Required: true, URL: "http://api/health", ExpectedStatus: 200}}, RequiredChecks: []string{"health"}, Transitions: []spec.Transition{{ID: "from-baseline", FromRelease: "baseline", Operations: []string{"deploy"}, Recovery: "previous"}}, Recovery: []spec.Recovery{{ID: "previous", ToRelease: "baseline", Operations: []spec.Operation{{ID: "restore", Type: "helm", Idempotent: true}}}}}}
		r.Metadata = spec.Metadata{Application: "demo", Version: version, Channel: "stable", Sequence: int64(n + 1)}
		release := filepath.Join(dir, "release-"+version+".json")
		if err := spec.Write(release, r); err != nil {
			t.Fatal(err)
		}
		cache := filepath.Join(dir, "cache")
		lock, err := bundle.Lock(context.Background(), release, cache)
		if err != nil {
			t.Fatal(err)
		}
		archive := filepath.Join(dir, "release-"+version+".cinder")
		if err := bundle.Build(context.Background(), lock, cache, archive, key, "release"); err != nil {
			t.Fatal(err)
		}
		v, err := bundle.Verify(context.Background(), archive, policy)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { v.Close() })
		versions = append(versions, v)
	}
	return versions[0], versions[1], policy
}

func TestDeltaReconstructionAndMissingBase(t *testing.T) {
	base, target, policy := deltaFixture(t)
	dir := filepath.Join(t.TempDir(), "delta")
	m, err := CreateDelta(context.Background(), base, target, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Changed) == 0 || len(m.Changed) >= len(target.Index.Payloads) {
		t.Fatalf("did not reuse base content: %+v", m)
	}
	chart, err := target.Asset("cinderlock-chart")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range m.Changed {
		if d.Digest == chart.Digest {
			t.Fatal("unchanged chart was needlessly retransferred")
		}
	}
	out := filepath.Join(t.TempDir(), "reconstructed.cinder")
	if _, err := ReconstructDelta(context.Background(), dir, base, policy, out); err != nil {
		t.Fatal(err)
	}
	v, err := bundle.Verify(context.Background(), out, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if v.Digest != target.Digest {
		t.Fatal("reconstruction changed target identity")
	}
	if _, err := ReconstructDelta(context.Background(), dir, target, policy, filepath.Join(t.TempDir(), "wrong.cinder")); err == nil {
		t.Fatal("wrong recipient base accepted")
	}
	changed, _ := bundle.BlobPath(dir, m.Changed[0].Digest)
	os.WriteFile(changed, []byte("damaged"), 0600)
	bad := filepath.Join(t.TempDir(), "corrupt.cinder")
	if _, err := ReconstructDelta(context.Background(), dir, base, policy, bad); err == nil {
		t.Fatal("corrupt delta accepted")
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("invalid reconstruction published")
	}
}
