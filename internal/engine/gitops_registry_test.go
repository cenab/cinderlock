package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	ociSpec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestGitOpsImportedGraphReadBoundariesRequireAvailableExactClosure(t *testing.T) {
	e, p, v, policy, a, registry := stagedImageFixture(t)
	ctx := context.Background()
	result, err := e.Apply(ctx, p, v, policy, a, false)
	if err != nil || result.State != "artifacts_staged" {
		t.Fatal("actual graph staging failed", err, result.State)
	}
	options, err := e.registryOptions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	destination := e.Site.Spec.Registry + "/runner"
	registry.Lock()
	before := registry.mutations
	registry.Unlock()
	if before == 0 {
		t.Fatal("graph staging did not exercise registry mutations")
	}
	t.Cleanup(func() {
		registry.Lock()
		defer registry.Unlock()
		if registry.mutations != before {
			t.Error("image evidence reads attempted a repository mutation")
		}
	})
	if err = bundle.ImportedImageAvailable(ctx, v, "runner", destination, options); err != nil {
		t.Fatal("addressed closure unavailable after verified copy", err)
	}
	if err = bundle.VerifyImportedImage(ctx, v, "runner", destination, options); err != nil {
		t.Fatal("copied bytes failed current audit", err)
	}
	var layer string
	registry.Lock()
	for name := range registry.objects {
		if strings.Contains(name, "/blobs/") {
			layer = name
			break
		}
	}
	original, ok := registry.objects[layer]
	delete(registry.objects, layer)
	registry.Unlock()
	if !ok {
		t.Fatal("staged image has no addressed blob")
	}
	if err = bundle.ImportedImageAvailable(ctx, v, "runner", destination, options); err == nil {
		t.Fatal("missing addressed image blob was accepted")
	}
	if err = bundle.VerifyImportedImage(ctx, v, "runner", destination, options); err == nil {
		t.Fatal("missing image bytes were verified")
	}
	registry.Lock()
	registry.objects[layer] = append(original, byte('x'))
	registry.Unlock()
	if err = bundle.ImportedImageAvailable(ctx, v, "runner", destination, options); err == nil {
		t.Fatal("inconsistent addressed descriptor was accepted")
	}
	if err = bundle.VerifyImportedImage(ctx, v, "runner", destination, options); err == nil {
		t.Fatal("changed image bytes were verified")
	}
	registry.Lock()
	registry.objects[layer] = original
	registry.Unlock()
	if err = bundle.ImportedImageAvailable(ctx, v, "runner", destination+"-missing", options); err == nil {
		t.Fatal("missing destination repository was accepted")
	}
	if err = bundle.VerifyImportedImage(ctx, v, "runner", destination+"-missing", options); err == nil {
		t.Fatal("missing destination repository was verified")
	}
	if err = bundle.ImportedImageAvailable(ctx, v, "runner", destination+"@"+v.Index.Lock.Assets[0].Digest, options); err == nil {
		t.Fatal("conflicting addressed destination was accepted")
	}
	if err = bundle.VerifyImportedImage(ctx, v, "runner", destination+":latest", options); err == nil {
		t.Fatal("tagged destination was verified")
	}
	asset := v.Index.Lock.Assets[0]
	rootPath, err := bundle.BlobPath(v.Root, asset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest ociSpec.Manifest
	if err = json.Unmarshal(rootBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"consistent duplicate", "duplicate with URL", "conflicting size", "conflicting media type"} {
		t.Run(mode, func(t *testing.T) {
			changed := manifest
			duplicate := manifest.Layers[0]
			switch mode {
			case "duplicate with URL":
				duplicate.URLs = []string{"https://unadmitted.invalid/layer"}
			case "conflicting size":
				duplicate.Size++
			case "conflicting media type":
				duplicate.MediaType = ociSpec.MediaTypeImageLayerGzip
			}
			changed.Layers = append(append([]ociSpec.Descriptor{}, manifest.Layers...), duplicate)
			data, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			digest, size, err := bundle.Store(ctx, v.Root, bytes.NewReader(data), bundle.MaxMetadataBytes)
			if err != nil {
				t.Fatal(err)
			}
			root := *asset.RootDescriptor
			root.Digest, root.Size = digest, size
			altered := asset
			altered.Digest, altered.RootDescriptor = digest, &root
			altered.Files = append([]spec.FileRecord{}, asset.Files...)
			for i := range altered.Files {
				if altered.Files[i].Digest == asset.Digest {
					altered.Files[i].Digest, altered.Files[i].Size = digest, size
				}
			}
			v.Index.Lock.Assets[0] = altered
			registry.Lock()
			registry.objects["offline/runner/manifests/"+digest] = data
			registry.media["offline/runner/manifests/"+digest] = root.MediaType
			registry.Unlock()
			err = bundle.ImportedImageAvailable(ctx, v, "runner", destination, options)
			if (err == nil) != (mode == "consistent duplicate") {
				t.Fatalf("unexpected known closure observation: %v", err)
			}
		})
	}
	v.Index.Lock.Assets[0] = asset
	v.Index.Lock.Assets[0].Files = append(v.Index.Lock.Assets[0].Files, spec.FileRecord{Digest: spec.Hash([]byte("unreferenced")), Size: 12})
	if err = bundle.ImportedImageAvailable(ctx, v, "runner", destination, options); err == nil {
		t.Fatal("unreferenced signed file was accepted as part of the addressed closure")
	}
}

func TestGitOpsImportedImageBoundsBeforeDestinationRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name   string
		change func(*spec.LockedAsset)
	}{
		{"missing root", func(a *spec.LockedAsset) { a.RootDescriptor = nil }},
		{"different root digest", func(a *spec.LockedAsset) { a.RootDescriptor.Digest = spec.Hash([]byte("different")) }},
		{"unsupported root media type", func(a *spec.LockedAsset) { a.RootDescriptor.MediaType = ociSpec.MediaTypeImageLayer }},
		{"oversized root", func(a *spec.LockedAsset) { a.RootDescriptor.Size = bundle.MaxMetadataBytes + 1 }},
		{"empty inventory", func(a *spec.LockedAsset) { a.Files = nil }},
		{"too many file records", func(a *spec.LockedAsset) {
			file := a.Files[0]
			a.Files = make([]spec.FileRecord, bundle.MaxMembers+1)
			for i := range a.Files {
				a.Files[i] = file
			}
		}},
		{"invalid file digest", func(a *spec.LockedAsset) {
			a.Files = append(a.Files, spec.FileRecord{Digest: "sha256:invalid", Size: 1})
		}},
		{"negative file size", func(a *spec.LockedAsset) {
			a.Files = append(a.Files, spec.FileRecord{Digest: spec.Hash([]byte("layer")), Size: -1})
		}},
		{"aggregate byte bound", func(a *spec.LockedAsset) {
			a.Files = append(a.Files, spec.FileRecord{Digest: spec.Hash([]byte("layer")), Size: bundle.MaxPayloadBytes})
		}},
		{"conflicting file sizes", func(a *spec.LockedAsset) {
			file := a.Files[0]
			file.Size++
			a.Files = append(a.Files, file)
		}},
		{"root absent from inventory", func(a *spec.LockedAsset) { a.Files[0].Digest = spec.Hash([]byte("other")) }},
		{"root size mismatch", func(a *spec.LockedAsset) { a.Files[0].Size++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := spec.Descriptor{Digest: spec.Hash([]byte("manifest")), Size: 8, MediaType: ociSpec.MediaTypeImageManifest}
			asset := spec.LockedAsset{ID: "runner", Type: "image", Digest: root.Digest, RootDescriptor: &root, Files: []spec.FileRecord{{Digest: root.Digest, Size: root.Size}}}
			test.change(&asset)
			v := &bundle.Verified{Index: spec.BundleIndex{Lock: spec.ReleaseLock{Assets: []spec.LockedAsset{asset}}}}
			err := bundle.ImportedImageAvailable(ctx, v, asset.ID, "127.0.0.1:1/offline/runner", bundle.RegistryOptions{PlainHTTP: true})
			if err == nil || errors.Is(err, context.Canceled) {
				t.Fatalf("invalid locked image reached destination observation: %v", err)
			}
		})
	}
}

func TestGitOpsImportedImageAvailabilityUsesExactRegistryMediaTypes(t *testing.T) {
	e, p, v, policy, a, registry := stagedImageFixture(t)
	asset := &v.Index.Lock.Assets[0]
	rootPath, err := bundle.BlobPath(v.Root, asset.Digest)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest ociSpec.Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Layers[0].MediaType = "application/vnd.example.index.v1+json"
	body, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest, size, err := bundle.Store(context.Background(), v.Root, bytes.NewReader(body), bundle.MaxMetadataBytes)
	if err != nil {
		t.Fatal(err)
	}
	for i := range asset.Files {
		if asset.Files[i].Digest == asset.Digest {
			asset.Files[i].Digest, asset.Files[i].Size = digest, size
		}
	}
	asset.Digest, asset.RootDescriptor.Digest, asset.RootDescriptor.Size = digest, digest, size
	result, err := e.Apply(context.Background(), p, v, policy, a, false)
	if err != nil || result.State != "artifacts_staged" {
		t.Fatalf("importer rejected the valid blob media type: %v %#v", err, result)
	}
	options, err := e.registryOptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	registry.Lock()
	mutations := registry.mutations
	registry.Unlock()
	if err := bundle.ImportedImageAvailable(context.Background(), v, "runner", e.Site.Spec.Registry+"/runner", options); err != nil {
		t.Fatal("successfully staged addressed blob became falsely unavailable", err)
	}
	registry.Lock()
	defer registry.Unlock()
	if registry.mutations != mutations {
		t.Fatal("availability observation mutated the registry")
	}
}

func TestGitOpsImportedMetadataAvailabilityDoesNotAuditBytes(t *testing.T) {
	e, p, v, policy, a, registry := stagedImageFixture(t)
	result, err := e.Apply(context.Background(), p, v, policy, a, false)
	if err != nil || result.State != "artifacts_staged" {
		t.Fatal("actual staging did not complete", err)
	}
	options, err := e.registryOptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	registry.Lock()
	for name, original := range registry.objects {
		if strings.Contains(name, "/blobs/") && len(original) > 0 {
			registry.advertisedDigest = map[string]string{name: spec.Hash(original)}
			changed := append([]byte{}, original...)
			changed[0] ^= 1
			registry.objects[name] = changed
			break
		}
	}
	gets, heads, mutations := registry.gets, registry.heads, registry.mutations
	registry.Unlock()
	if registry.advertisedDigest == nil {
		t.Fatal("fixture has no bytes to corrupt")
	}
	destination := e.Site.Spec.Registry + "/runner"
	if err := bundle.ImportedImageAvailable(context.Background(), v, "runner", destination, options); err != nil {
		t.Fatal("unchanged addressed metadata should remain available", err)
	}
	registry.Lock()
	metadataGets, metadataHeads := registry.gets-gets, registry.heads-heads
	registry.Unlock()
	if metadataGets != 0 || metadataHeads == 0 {
		t.Fatalf("availability streamed content: GET=%d HEAD=%d", metadataGets, metadataHeads)
	}
	if err := bundle.VerifyImportedImage(context.Background(), v, "runner", destination, options); err == nil {
		t.Fatal("full byte audit accepted same-size changed bytes behind unchanged metadata")
	}
	registry.Lock()
	defer registry.Unlock()
	if registry.gets == gets || registry.mutations != mutations {
		t.Fatalf("byte audit did not fetch content read-only: GET=%d mutations=%d", registry.gets-gets, registry.mutations-mutations)
	}
}
