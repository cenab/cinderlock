package bundle

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	digest "github.com/opencontainers/go-digest"
	ociSpec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

type RegistryOptions struct {
	PlainHTTP            bool     `json:"plainHTTP,omitempty"`
	CAFile               string   `json:"caFile,omitempty"`
	Username             string   `json:"username,omitempty"`
	Password             string   `json:"password,omitempty"`
	AllowedRedirectHosts []string `json:"allowedRedirectHosts,omitempty"`
	AllowedAuthHosts     []string `json:"allowedAuthHosts,omitempty"`
}

func registryClient(reference string, opts RegistryOptions) (*remote.Repository, error) {
	r, err := remote.NewRepository(reference)
	if err != nil {
		return nil, err
	}
	r.PlainHTTP = opts.PlainHTTP
	r.MaxMetadataBytes = MaxMetadataBytes
	scheme := "https://"
	if opts.PlainHTTP {
		scheme = "http://"
	}
	client, err := sourceHTTPClient(scheme+r.Reference.Registry, opts)
	if err != nil {
		return nil, err
	}
	r.Client = &auth.Client{Client: client, Cache: auth.NewCache(), Credential: auth.StaticCredential(r.Reference.Registry, auth.Credential{Username: opts.Username, Password: opts.Password})}
	return r, nil
}

func sourceHTTPClient(origin string, opts RegistryOptions) (*http.Client, error) {
	originURL, err := url.Parse(origin)
	if err != nil || !validRedirectHost(originURL.Host) || originURL.User != nil || originURL.RawQuery != "" || originURL.Path != "" || originURL.Fragment != "" || (originURL.Scheme != "https" && !(opts.PlainHTTP && originURL.Scheme == "http")) {
		return nil, spec.Err(2, "source client requires an explicit admitted HTTP(S) origin")
	}
	for _, host := range append(append([]string{}, opts.AllowedRedirectHosts...), opts.AllowedAuthHosts...) {
		if !validRedirectHost(host) {
			return nil, spec.Err(2, "invalid admitted redirect host")
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.CAFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		b, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("registry CA file contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 90 * time.Second}
	return &http.Client{Transport: sourceTransport{base: transport, origin: originURL, options: opts}, CheckRedirect: func(req *http.Request, via []*http.Request) error { return checkRedirect(req, via, opts) }}, nil
}

// sourceTransport admits every request, including token realms constructed by
// the registry authentication client without an HTTP redirect. Download-host
// admission never grants authority to receive credentials or request bodies.
type sourceTransport struct {
	base    http.RoundTripper
	origin  *url.URL
	options RegistryOptions
}

func (t sourceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.admit(req); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	return t.base.RoundTrip(req)
}

func (t sourceTransport) admit(req *http.Request) error {
	u := req.URL
	if u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("source request has an unapproved transport or embedded credentials")
	}
	if u.Host == t.origin.Host {
		if u.Scheme != t.origin.Scheme {
			return errors.New("source request transport differs from its admitted origin")
		}
		return nil
	}
	for _, host := range t.options.AllowedAuthHosts {
		if u.Host == host && u.Scheme == "https" {
			return nil
		}
	}
	for _, host := range t.options.AllowedRedirectHosts {
		if u.Host != host {
			continue
		}
		if u.Scheme != "https" && (t.origin.Scheme != "http" || !t.options.PlainHTTP) {
			return errors.New("download request would weaken transport security")
		}
		if (req.Method != http.MethodGet && req.Method != http.MethodHead) || req.Body != nil || req.Header.Get("Authorization") != "" || req.Header.Get("Proxy-Authorization") != "" || req.Header.Get("Cookie") != "" {
			return errors.New("download host is not admitted to receive authentication or request bodies")
		}
		return nil
	}
	return errors.New("source request host is outside the admitted origin, authentication, and download scopes")
}

func checkRedirect(req *http.Request, via []*http.Request, opts RegistryOptions) error {
	if len(via) == 0 || len(via) > 5 || req.URL.User != nil {
		return errors.New("unapproved redirect")
	}
	if req.URL.Scheme != "https" && !opts.PlainHTTP || via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("redirect would weaken transport security")
	}
	if req.URL.Host != via[0].URL.Host {
		if req.Body != nil || (req.Method != http.MethodGet && req.Method != http.MethodHead) {
			return errors.New("cross-host redirects with a body or mutation are forbidden")
		}
		allowed := false
		for _, host := range opts.AllowedRedirectHosts {
			if host == req.URL.Host {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New("redirect host is not explicitly admitted")
		}
		req.Header.Del("Authorization")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Cookie")
	}
	return nil
}
func validRedirectHost(host string) bool {
	if strings.ContainsAny(host, "* \t\r\n") {
		return false
	}
	u, err := url.Parse("https://" + host)
	return err == nil && u.Host == host && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}
func sourceError(host, action string, err error) error {
	code := 10
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		code = 17
	}
	status := "transport, authentication, or admitted-host check failed"
	var response *errcode.ErrorResponse
	if errors.As(err, &response) {
		status = fmt.Sprintf("HTTP %d", response.StatusCode)
	}
	return &spec.Error{Code: code, Message: action + " for " + host + ": " + status, Cause: err}
}

func lockImageWithOptions(ctx context.Context, asset spec.Asset, workspace, cache string, options RegistryOptions) (locked spec.LockedAsset, resultErr error) {
	sourceHost := "local OCI layout"
	defer func() {
		if resultErr != nil && sourceHost != "local OCI layout" {
			resultErr = sourceError(sourceHost, "image source transfer", resultErr)
		}
	}()
	locked = spec.LockedAsset{ID: asset.ID, Type: asset.Type, Source: asset.Source, Platform: asset.Platform, License: asset.License}
	var source content.ReadOnlyStorage
	var root ociSpec.Descriptor
	var err error
	if strings.HasPrefix(asset.Source, "oci:") {
		parts := strings.SplitN(strings.TrimPrefix(asset.Source, "oci:"), "#", 2)
		p, err := within(workspace, parts[0])
		if err != nil {
			return locked, err
		}
		store, err := oci.New(p)
		if err != nil {
			return locked, err
		}
		ref := "latest"
		if len(parts) == 2 {
			ref = parts[1]
		}
		root, err = store.Resolve(ctx, ref)
		if err != nil {
			return locked, err
		}
		source = store
	} else {
		ref, err := registry.ParseReference(asset.Source)
		if err != nil {
			return locked, fmt.Errorf("image %s: explicit registry/repository reference required: %w", asset.ID, err)
		}
		sourceHost = ref.Registry
		repo, err := registryClient(ref.Registry+"/"+ref.Repository, options)
		if err != nil {
			return locked, err
		}
		root, err = repo.Resolve(ctx, ref.ReferenceOrDefault())
		if err != nil {
			return locked, sourceError(ref.Registry, "image resolution", err)
		}
		source = repo
	}
	if root.Size < 0 || root.Size > MaxMetadataBytes {
		return locked, errors.New("image root manifest exceeds metadata limit")
	}
	platform := strings.Split(asset.Platform, "/")
	if asset.Platform != "" && (len(platform) < 2 || len(platform) > 3) {
		return locked, errors.New("platform must be os/architecture[/variant]")
	}
	if asset.Platform != "" && (root.MediaType == ociSpec.MediaTypeImageIndex || root.MediaType == "application/vnd.docker.distribution.manifest.list.v2+json") {
		if len(platform) < 2 || len(platform) > 3 {
			return locked, errors.New("platform must be os/architecture[/variant]")
		}
		children, err := content.Successors(ctx, source, root)
		if err != nil {
			return locked, err
		}
		found := false
		for _, child := range children {
			if child.Platform != nil && child.Platform.OS == platform[0] && child.Platform.Architecture == platform[1] && (len(platform) == 2 || child.Platform.Variant == platform[2]) {
				if found {
					return locked, errors.New("ambiguous image platform selection")
				}
				root = child
				found = true
			}
		}
		if !found {
			return locked, fmt.Errorf("image has no manifest for platform %s", asset.Platform)
		}
	}
	if asset.Platform != "" && (root.MediaType == ociSpec.MediaTypeImageManifest || root.MediaType == "application/vnd.docker.distribution.manifest.v2+json") {
		children, err := content.Successors(ctx, source, root)
		if err != nil {
			return locked, err
		}
		var config *ociSpec.Descriptor
		for _, d := range children {
			if d.MediaType == ociSpec.MediaTypeImageConfig || d.MediaType == "application/vnd.docker.container.image.v1+json" {
				copy := d
				config = &copy
				break
			}
		}
		if config == nil || config.Size < 0 || config.Size > MaxMetadataBytes {
			return locked, errors.New("image configuration is missing or oversized")
		}
		r, err := source.Fetch(ctx, *config)
		if err != nil {
			return locked, err
		}
		b, err := io.ReadAll(io.LimitReader(r, config.Size+1))
		r.Close()
		if err != nil {
			return locked, err
		}
		if int64(len(b)) != config.Size {
			return locked, errors.New("image configuration size mismatch")
		}
		var observed struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Variant      string `json:"variant"`
		}
		if err := json.Unmarshal(b, &observed); err != nil {
			return locked, err
		}
		if observed.OS != platform[0] || observed.Architecture != platform[1] || (len(platform) == 3 && observed.Variant != platform[2] && (root.Platform == nil || root.Platform.Variant != platform[2])) {
			return locked, fmt.Errorf("image configuration does not match declared platform %s", asset.Platform)
		}
	}
	if asset.Digest != "" && root.Digest.String() != asset.Digest {
		return locked, fmt.Errorf("image %s digest mismatch", asset.ID)
	}
	if root.MediaType != ociSpec.MediaTypeImageManifest && root.MediaType != ociSpec.MediaTypeImageIndex && root.MediaType != "application/vnd.docker.distribution.manifest.v2+json" && root.MediaType != "application/vnd.docker.distribution.manifest.list.v2+json" {
		return locked, errors.New("unsupported image root media type")
	}
	dest, err := oci.New(cache)
	if err != nil {
		return locked, err
	}
	if err := oras.CopyGraph(ctx, source, dest, root, oras.DefaultCopyGraphOptions); err != nil {
		return locked, sourceError("declared source", "image acquisition", err)
	}
	files, err := imageGraph(ctx, dest, root)
	if err != nil {
		return locked, err
	}
	for _, f := range files {
		locked.Size += f.Size
	}
	locked.Digest = root.Digest.String()
	locked.MediaType = root.MediaType
	locked.Files = files
	locked.RootDescriptor = &spec.Descriptor{Path: "blobs/sha256/" + root.Digest.Encoded(), Digest: root.Digest.String(), Size: root.Size, MediaType: root.MediaType}
	return locked, nil
}

func imageGraph(ctx context.Context, source content.ReadOnlyStorage, root ociSpec.Descriptor) ([]spec.FileRecord, error) {
	seen := map[string]ociSpec.Descriptor{}
	queue := []ociSpec.Descriptor{root}
	var files []spec.FileRecord
	var total int64
	for len(queue) > 0 {
		if len(seen) >= MaxMembers {
			return nil, errors.New("image graph exceeds member limit")
		}
		d := queue[0]
		queue = queue[1:]
		if len(d.URLs) > 0 {
			return nil, spec.Err(10, "external OCI descriptor URLs are unsupported; supply a self-contained image graph")
		}
		if previous, ok := seen[d.Digest.String()]; ok {
			if previous.Size != d.Size || previous.MediaType != d.MediaType {
				return nil, errors.New("conflicting OCI descriptors for the same content")
			}
			continue
		}
		seen[d.Digest.String()] = d
		if !ValidDigest(d.Digest.String()) || d.Size < 0 || d.Size > MaxPayloadBytes-total {
			return nil, errors.New("invalid image descriptor")
		}
		if (strings.Contains(d.MediaType, "manifest") || strings.Contains(d.MediaType, "index")) && d.Size > MaxMetadataBytes {
			return nil, errors.New("image manifest exceeds metadata limit")
		}
		r, err := source.Fetch(ctx, d)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(h, &contextReader{ctx: ctx, r: io.LimitReader(r, d.Size+1)})
		closeErr := r.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, err
		}
		if n != d.Size || hex.EncodeToString(h.Sum(nil)) != d.Digest.Encoded() {
			return nil, fmt.Errorf("image blob %s failed full-content verification", d.Digest)
		}
		files = append(files, spec.FileRecord{Path: "blobs/sha256/" + d.Digest.Encoded(), Digest: d.Digest.String(), Size: d.Size, Mode: 0644})
		total += d.Size
		children, err := content.Successors(ctx, source, d)
		if err != nil {
			return nil, err
		}
		queue = append(queue, children...)
	}
	return files, nil
}

type verifiedStorage struct{ root string }

func (s verifiedStorage) Fetch(ctx context.Context, d ociSpec.Descriptor) (io.ReadCloser, error) {
	if err := VerifyBlob(ctx, s.root, d.Digest.String(), d.Size); err != nil {
		return nil, err
	}
	p, _ := BlobPath(s.root, d.Digest.String())
	return os.Open(p)
}
func (s verifiedStorage) Exists(ctx context.Context, d ociSpec.Descriptor) (bool, error) {
	err := VerifyBlob(ctx, s.root, d.Digest.String(), d.Size)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func ImportImage(ctx context.Context, v *Verified, assetID, destination string, opts RegistryOptions) (destinationRef string, resultErr error) {
	a, err := v.Asset(assetID)
	if err != nil {
		return "", err
	}
	if a.Type != "image" || a.RootDescriptor == nil {
		return "", errors.New("asset is not an OCI image")
	}
	root := ociSpec.Descriptor{Digest: digest.Digest(a.RootDescriptor.Digest), Size: a.RootDescriptor.Size, MediaType: a.RootDescriptor.MediaType}
	repo, err := registryClient(destination, opts)
	if err != nil {
		return "", err
	}
	if repo.Reference.Reference != "" {
		return "", errors.New("destination must be a repository without tag or digest")
	}
	defer func() {
		if resultErr != nil {
			resultErr = sourceError(repo.Reference.Registry, "destination image import", resultErr)
		}
	}()
	if err := oras.CopyGraph(ctx, verifiedStorage{v.Root}, repo, root, oras.DefaultCopyGraphOptions); err != nil {
		return "", err
	}
	if _, err := imageGraph(ctx, repo, root); err != nil {
		return "", err
	}
	return destination + "@" + root.Digest.String(), nil
}

func within(root, p string) (string, error) {
	if p == "" {
		return "", errors.New("empty input path")
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("artifact source escapes admitted workspace")
	}
	return p, nil
}
