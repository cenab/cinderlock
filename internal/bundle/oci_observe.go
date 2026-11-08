package bundle

import (
	"context"
	"errors"

	"github.com/cenab/cinderlock/internal/spec"
	digest "github.com/opencontainers/go-digest"
	ociSpec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
)

func importedImageTarget(v *Verified, assetID, destination string, opts RegistryOptions) (spec.LockedAsset, ociSpec.Descriptor, *remote.Repository, error) {
	if v == nil {
		return spec.LockedAsset{}, ociSpec.Descriptor{}, nil, errors.New("verified image bundle is unavailable")
	}
	a, err := v.Asset(assetID)
	if err != nil {
		return a, ociSpec.Descriptor{}, nil, err
	}
	if a.Type != "image" || a.RootDescriptor == nil || a.RootDescriptor.Digest != a.Digest || !ValidDigest(a.Digest) || a.RootDescriptor.Size <= 0 || a.RootDescriptor.Size > MaxMetadataBytes {
		return a, ociSpec.Descriptor{}, nil, errors.New("asset is not an exact OCI image")
	}
	switch a.RootDescriptor.MediaType {
	case ociSpec.MediaTypeImageManifest, ociSpec.MediaTypeImageIndex, "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.docker.distribution.manifest.list.v2+json":
	default:
		return a, ociSpec.Descriptor{}, nil, errors.New("unsupported image root media type")
	}
	root := ociSpec.Descriptor{Digest: digest.Digest(a.RootDescriptor.Digest), Size: a.RootDescriptor.Size, MediaType: a.RootDescriptor.MediaType}
	repo, err := registryClient(destination, opts)
	if err != nil {
		return a, root, nil, err
	}
	if repo.Reference.Reference != "" {
		return a, root, nil, errors.New("destination must be a repository without tag or digest")
	}
	return a, root, repo, nil
}

// VerifyImportedImage reads and hashes the complete addressed destination graph.
// It performs no copy, tag, upload, or repository mutation.
func VerifyImportedImage(ctx context.Context, v *Verified, assetID, destination string, opts RegistryOptions) error {
	_, root, repo, err := importedImageTarget(v, assetID, destination, opts)
	if err != nil {
		return err
	}
	if _, err := imageGraph(ctx, repo, root); err != nil {
		return sourceError(repo.Reference.Registry, "destination image verification", err)
	}
	return nil
}

// ImportedImageAvailable checks the signed graph's current addressed metadata.
// Layer availability is not a fresh byte audit, a completed copy, or a future pull guarantee.
func ImportedImageAvailable(ctx context.Context, v *Verified, assetID, destination string, opts RegistryOptions) (resultErr error) {
	a, root, repo, err := importedImageTarget(v, assetID, destination, opts)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = sourceError(repo.Reference.Registry, "destination image availability", resultErr)
		}
	}()
	if len(a.Files) == 0 || len(a.Files) > MaxMembers {
		return errors.New("locked image closure is unavailable or exceeds its bound")
	}
	known := map[string]int64{}
	var total int64
	for _, file := range a.Files {
		if !ValidDigest(file.Digest) || file.Size < 0 {
			return errors.New("invalid locked image file descriptor")
		}
		if n, exists := known[file.Digest]; exists {
			if n != file.Size {
				return errors.New("conflicting locked image closure sizes")
			}
			continue
		}
		if file.Size > MaxPayloadBytes-total {
			return errors.New("locked image closure exceeds its byte bound")
		}
		known[file.Digest] = file.Size
		total += file.Size
	}
	seen := map[string]ociSpec.Descriptor{}
	queue := []ociSpec.Descriptor{root}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if len(d.URLs) > 0 {
			return errors.New("external addressed image descriptor URLs are unsupported")
		}
		if previous, exists := seen[d.Digest.String()]; exists {
			if previous.Size != d.Size || previous.MediaType != d.MediaType {
				return errors.New("conflicting addressed image descriptors")
			}
			continue
		}
		expected, locked := known[d.Digest.String()]
		if !locked || expected != d.Size {
			return errors.New("unsupported addressed image closure")
		}
		seen[d.Digest.String()] = d
		manifest := false
		switch d.MediaType {
		case ociSpec.MediaTypeImageManifest, ociSpec.MediaTypeImageIndex, "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.oci.artifact.manifest.v1+json":
			manifest = true
		}
		var actual ociSpec.Descriptor
		if manifest {
			if d.Size > MaxMetadataBytes {
				return errors.New("addressed image metadata exceeds its bound")
			}
			actual, err = repo.Manifests().Resolve(ctx, d.Digest.String())
		} else {
			actual, err = repo.Blobs().Resolve(ctx, d.Digest.String())
		}
		if err != nil {
			return err
		}
		if actual.Digest != d.Digest || actual.Size != d.Size || manifest && actual.MediaType != d.MediaType {
			return errors.New("addressed image metadata differs from the locked descriptor")
		}
		children, err := content.Successors(ctx, verifiedStorage{v.Root}, d)
		if err != nil {
			return err
		}
		queue = append(queue, children...)
	}
	if len(seen) != len(known) {
		return errors.New("addressed image closure differs from the signed file inventory")
	}
	return nil
}
