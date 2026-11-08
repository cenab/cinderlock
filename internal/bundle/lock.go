package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
	"oras.land/oras-go/v2/registry"
)

type LockOptions struct {
	Registries map[string]RegistryOptions `json:"registries"`
}

func ReadLockOptions(path string) (LockOptions, error) {
	var opts LockOptions
	b, err := readPrivateFile(path, 1<<20)
	if err != nil {
		return opts, err
	}
	if err := DecodeJSON(b, &opts); err != nil {
		return opts, err
	}
	return opts, validateLockOptions(opts)
}
func validateLockOptions(opts LockOptions) error {
	if len(opts.Registries) > 256 {
		return spec.Err(2, "too many source authentication scopes")
	}
	for host, o := range opts.Registries {
		ref, err := registry.ParseReference(host + "/cinderlock-auth-scope")
		if err != nil || ref.Registry != host || strings.Contains(host, "/") {
			return spec.Err(2, "source authentication scope must be an exact registry host")
		}
		if len(o.Username) > 16384 || len(o.Password) > 16384 {
			return spec.Err(2, "source credentials exceed limit")
		}
		for _, h := range append(append([]string{}, o.AllowedRedirectHosts...), o.AllowedAuthHosts...) {
			if !validRedirectHost(h) {
				return spec.Err(2, "invalid source redirect host")
			}
		}
	}
	return nil
}

func Lock(ctx context.Context, releasePath, cacheDir string) (spec.ReleaseLock, error) {
	return LockWithOptions(ctx, releasePath, cacheDir, LockOptions{})
}
func LockWithOptions(ctx context.Context, releasePath, cacheDir string, options LockOptions) (spec.ReleaseLock, error) {
	var release spec.Release
	var locked spec.ReleaseLock
	if err := validateLockOptions(options); err != nil {
		return locked, err
	}
	unlock, err := acquireCache(ctx, cacheDir, true)
	if err != nil {
		return locked, err
	}
	defer unlock()
	if err := spec.Read(releasePath, &release); err != nil {
		return locked, err
	}
	if err := spec.ValidateRelease(release); err != nil {
		return locked, err
	}
	workspace, err := filepath.Abs(filepath.Dir(releasePath))
	if err != nil {
		return locked, err
	}
	digest, err := spec.Digest(release)
	if err != nil {
		return locked, err
	}
	locked = spec.ReleaseLock{Header: spec.NewHeader("ReleaseLock"), Release: release, SourceDigest: digest, Toolchain: spec.Toolchain{Go: runtime.Version(), CLI: "cinderlock-dev"}}
	locked.Metadata = release.Metadata
	assets := append([]spec.Asset{}, release.Spec.Assets...)
	assets = append(assets, spec.Asset{ID: "cinderlock-chart", Type: "file-tree", Source: release.Spec.Deployment.Chart})
	for i, v := range release.Spec.Deployment.Values {
		assets = append(assets, spec.Asset{ID: fmt.Sprintf("cinderlock-values-%d", i), Type: "file", Source: v})
	}
	for _, asset := range assets {
		if err := ctx.Err(); err != nil {
			return locked, err
		}
		var item spec.LockedAsset
		opts := RegistryOptions{}
		if asset.Type == "image" && !strings.HasPrefix(asset.Source, "oci:") {
			ref, e := registry.ParseReference(asset.Source)
			if e != nil {
				return locked, e
			}
			opts = options.Registries[ref.Registry]
		} else if u, e := url.Parse(asset.Source); e == nil && u.Scheme == "https" {
			opts = options.Registries[u.Host]
		}
		opts.AllowedRedirectHosts = append(append([]string{}, opts.AllowedRedirectHosts...), asset.AllowedRedirectHosts...)
		if asset.Type == "image" {
			item, err = lockImageWithOptions(ctx, asset, workspace, cacheDir, opts)
		} else {
			item, err = lockFilesWithOptions(ctx, asset, workspace, cacheDir, opts)
		}
		if err != nil {
			return locked, fmt.Errorf("lock asset %s: %w", asset.ID, err)
		}
		locked.Assets = append(locked.Assets, item)
	}
	images := map[string]bool{}
	for _, a := range locked.Assets {
		if a.Type == "image" {
			images[a.ID] = true
			images[a.Source] = true
			images[a.Source+"@"+a.Digest] = true
		}
	}
	for _, o := range release.Spec.Operations {
		if o.Image != "" && !images[o.Image] {
			return locked, fmt.Errorf("operation %s uses undeclared image %s", o.ID, o.Image)
		}
	}
	for _, c := range release.Spec.Checks {
		if c.Image != "" && !images[c.Image] {
			return locked, fmt.Errorf("check %s uses undeclared image %s", c.ID, c.Image)
		}
	}
	for _, r := range release.Spec.Recovery {
		for _, o := range r.Operations {
			if o.Image != "" && !images[o.Image] {
				return locked, fmt.Errorf("recovery %s uses undeclared image %s", r.ID, o.Image)
			}
		}
		for _, c := range r.Checks {
			if c.Image != "" && !images[c.Image] {
				return locked, fmt.Errorf("recovery check %s uses undeclared image %s", c.ID, c.Image)
			}
		}
	}
	identity, err := spec.Digest(locked)
	if err != nil {
		return locked, err
	}
	if err := retainCache(cacheDir, "lock:"+identity, locked.Assets); err != nil {
		return locked, err
	}
	return locked, nil
}

func lockFilesWithOptions(ctx context.Context, asset spec.Asset, workspace, cache string, options RegistryOptions) (spec.LockedAsset, error) {
	a := spec.LockedAsset{ID: asset.ID, Type: asset.Type, Source: asset.Source, License: asset.License, MediaType: asset.MediaType}
	u, err := url.Parse(asset.Source)
	if err != nil {
		return a, err
	}
	if u.Scheme == "https" {
		if !ValidDigest(asset.Digest) || u.User != nil || u.RawQuery != "" {
			return a, errors.New("HTTPS file inputs require a pinned digest and no embedded credentials")
		}
		client, err := sourceHTTPClient(u.Scheme+"://"+u.Host, options)
		if err != nil {
			return a, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.Source, nil)
		if err != nil {
			return a, err
		}
		if options.Username != "" || options.Password != "" {
			req.SetBasicAuth(options.Username, options.Password)
		}
		resp, err := client.Do(req)
		if err != nil {
			return a, sourceError(u.Host, "artifact download", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return a, fmt.Errorf("artifact source returned HTTP %d", resp.StatusCode)
		}
		d, size, err := Store(ctx, cache, resp.Body, MaxPayloadBytes)
		if err != nil {
			return a, err
		}
		if d != asset.Digest {
			return a, errors.New("downloaded artifact digest mismatch")
		}
		name := filepath.Base(u.Path)
		if !safeMember(name) {
			return a, errors.New("source filename is invalid")
		}
		a.Files = []spec.FileRecord{{Path: name, Digest: d, Size: size, Mode: 0644}}
		a.Digest = d
		a.Size = size
		return a, nil
	}
	if u.Scheme != "" {
		return a, fmt.Errorf("unsupported artifact scheme %s", u.Scheme)
	}
	p, err := within(workspace, asset.Source)
	if err != nil {
		return a, err
	}
	info, err := os.Stat(p)
	if err != nil {
		return a, err
	}
	if info.IsDir() {
		absCache, e := filepath.EvalSymlinks(cache)
		if e != nil {
			return a, e
		}
		absCache, e = filepath.Abs(absCache)
		if e != nil {
			return a, e
		}
		relative, e := filepath.Rel(p, absCache)
		if e != nil {
			return a, e
		}
		if relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return a, errors.New("artifact source contains its own content cache")
		}
	}
	if asset.ID == "cinderlock-chart" && !info.IsDir() {
		a.Type = "file"
	}
	add := func(name, file string) error {
		if !safeMember(name) {
			return fmt.Errorf("unsupported artifact path %q", name)
		}
		actual, err := within(workspace, file)
		if err != nil {
			return err
		}
		info, err := os.Stat(actual)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("artifact contains a non-regular file")
		}
		f, err := os.Open(actual)
		if err != nil {
			return err
		}
		d, n, err := Store(ctx, cache, f, MaxPayloadBytes-a.Size)
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		mode := uint32(0644)
		if info.Mode()&0111 != 0 {
			mode = 0755
		}
		a.Files = append(a.Files, spec.FileRecord{Path: filepath.ToSlash(name), Digest: d, Size: n, Mode: mode})
		a.Size += n
		if len(a.Files) > MaxMembers {
			return errors.New("artifact tree exceeds file-count limit")
		}
		return nil
	}
	if info.IsDir() {
		err = filepath.WalkDir(p, func(file string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(p, file)
			if err != nil {
				return err
			}
			return add(filepath.ToSlash(rel), file)
		})
	} else {
		err = add(filepath.Base(p), p)
	}
	if err != nil {
		return a, err
	}
	if len(a.Files) == 0 {
		return a, errors.New("artifact tree is empty")
	}
	sort.Slice(a.Files, func(i, j int) bool { return a.Files[i].Path < a.Files[j].Path })
	if len(a.Files) == 1 && !info.IsDir() {
		a.Digest = a.Files[0].Digest
	} else {
		a.Digest, err = spec.Digest(a.Files)
		if err != nil {
			return a, err
		}
	}
	if asset.Digest != "" && asset.Digest != a.Digest {
		return a, errors.New("artifact input digest mismatch")
	}
	// Portable provenance must not disclose a producer's absolute workspace path.
	if filepath.IsAbs(a.Source) {
		a.Source, err = filepath.Rel(workspace, p)
		if err != nil {
			return a, err
		}
		a.Source = filepath.ToSlash(a.Source)
	}
	return a, nil
}

func Materialize(v *Verified, assetID, outDir string) (string, error) {
	a, err := v.Asset(assetID)
	if err != nil {
		return "", err
	}
	if a.Type == "image" {
		return "", errors.New("use ImportImage for an OCI image")
	}
	if err := os.Mkdir(outDir, 0700); err != nil {
		return "", err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(outDir)
		}
	}()
	for _, f := range a.Files {
		if !safeMember(f.Path) {
			return "", errors.New("invalid materialized path")
		}
		if err := VerifyBlob(context.Background(), v.Root, f.Digest, f.Size); err != nil {
			return "", err
		}
		p := filepath.Join(outDir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return "", err
		}
		inPath, _ := BlobPath(v.Root, f.Digest)
		in, err := os.Open(inPath)
		if err != nil {
			return "", err
		}
		out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(f.Mode))
		if err != nil {
			in.Close()
			return "", err
		}
		_, err = io.CopyN(out, in, f.Size)
		in.Close()
		if err == nil {
			err = out.Sync()
		}
		closeErr := out.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return "", err
		}
	}
	complete = true
	if len(a.Files) == 1 && a.Type == "file" {
		return filepath.Join(outDir, filepath.FromSlash(a.Files[0].Path)), nil
	}
	return outDir, nil
}
