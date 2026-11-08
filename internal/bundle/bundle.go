package bundle

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	digest "github.com/opencontainers/go-digest"
	ociSpec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"
)

const IndexName = "cinderlock-index.json"

type Verified struct {
	Index  spec.BundleIndex
	Digest string
	Root   string
}

func (v *Verified) Close() error { return os.RemoveAll(v.Root) }
func (v *Verified) Asset(id string) (spec.LockedAsset, error) {
	for _, a := range v.Index.Lock.Assets {
		if a.ID == id {
			return a, nil
		}
	}
	return spec.LockedAsset{}, fmt.Errorf("locked asset %q is absent", id)
}

func Build(ctx context.Context, lock spec.ReleaseLock, cacheDir, out, keyPath, keyID string) error {
	unlock, err := acquireCache(ctx, cacheDir, true)
	if err != nil {
		return err
	}
	defer unlock()
	if !validKeyID(keyID) {
		return spec.Err(2, "invalid signing key ID")
	}
	key, err := ReadPrivateKey(keyPath)
	if err != nil {
		return err
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	keyFileDigest := spec.Hash(keyBytes)
	index := spec.BundleIndex{Header: spec.NewHeader("BundleIndex"), Domain: spec.BundleDomain, Lock: lock, RequiredCapabilities: []string{"bundle.v1"}}
	index.Metadata = lock.Release.Metadata
	payloads := map[string]spec.Descriptor{}
	for _, a := range lock.Assets {
		if a.Type == "image" {
			index.RequiredCapabilities = []string{"bundle.v1", "oci.v1"}
		}
		for _, f := range a.Files {
			if f.Digest == keyFileDigest {
				return spec.Err(12, "release inputs contain the signing private-key file")
			}
			if !ValidDigest(f.Digest) {
				return spec.Err(2, "invalid locked digest")
			}
			p := "blobs/sha256/" + f.Digest[7:]
			if old, ok := payloads[p]; ok && old.Size != f.Size {
				return spec.Err(2, "conflicting locked descriptor")
			}
			payloads[p] = spec.Descriptor{Path: p, Digest: f.Digest, Size: f.Size, MediaType: "application/octet-stream"}
		}
	}
	inventory, err := Inventory(lock)
	if err != nil {
		return err
	}
	inventoryBytes, err := spec.Canonical(inventory)
	if err != nil {
		return err
	}
	if int64(len(inventoryBytes)) > MaxMetadataBytes {
		return errors.New("component inventory exceeds metadata limit")
	}
	inventoryDigest, inventorySize, err := Store(ctx, cacheDir, bytes.NewReader(inventoryBytes), MaxMetadataBytes)
	if err != nil {
		return err
	}
	inventoryDescriptor := spec.Descriptor{Path: "blobs/sha256/" + inventoryDigest[7:], Digest: inventoryDigest, Size: inventorySize, MediaType: "application/vnd.cyclonedx+json"}
	index.Inventory = &inventoryDescriptor
	payloads[inventoryDescriptor.Path] = inventoryDescriptor
	index.RequiredCapabilities = append(index.RequiredCapabilities, "inventory.v1")
	for _, d := range payloads {
		index.Payloads = append(index.Payloads, d)
	}
	sort.Slice(index.Payloads, func(i, j int) bool { return index.Payloads[i].Path < index.Payloads[j].Path })
	if err := validateIndex(index); err != nil {
		return err
	}
	for _, d := range index.Payloads {
		if err := VerifyBlob(ctx, cacheDir, d.Digest, d.Size); err != nil {
			return err
		}
	}
	b, err := spec.Canonical(index)
	if err != nil {
		return err
	}
	if int64(len(b)) > MaxMetadataBytes {
		return errors.New("bundle index exceeds metadata limit")
	}
	retained := append([]spec.LockedAsset{}, lock.Assets...)
	retained = append(retained, spec.LockedAsset{Files: []spec.FileRecord{{Digest: inventoryDigest, Size: inventorySize}}})
	if err := retainCache(cacheDir, "bundle:"+spec.Hash(b), retained); err != nil {
		return err
	}
	sig, err := Sign(b, keyID, key)
	if err != nil {
		return err
	}
	sigBytes, err := spec.Canonical(sig)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = f.Close()
		if !complete {
			_ = os.Remove(out)
		}
	}()
	tw := tar.NewWriter(f)
	add := func(name string, size int64, r io.Reader) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: size, Typeflag: tar.TypeReg, Format: tar.FormatGNU}); err != nil {
			return err
		}
		_, err := io.CopyN(tw, &contextReader{ctx: ctx, r: r}, size)
		return err
	}
	if err := add(IndexName, int64(len(b)), bytes.NewReader(b)); err != nil {
		return err
	}
	if err := add("signatures/"+keyID+".sig", int64(len(sigBytes)), bytes.NewReader(sigBytes)); err != nil {
		return err
	}
	for _, d := range index.Payloads {
		p, _ := BlobPath(cacheDir, d.Digest)
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		err = add(d.Path, d.Size, in)
		closeErr := in.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func Verify(ctx context.Context, bundlePath string, policy spec.TrustPolicy) (_ *Verified, resultErr error) {
	defer func() {
		if resultErr != nil && spec.ExitCode(resultErr) == 19 {
			resultErr = &spec.Error{Code: 12, Message: "bundle verification failed: " + resultErr.Error(), Cause: resultErr}
		}
	}()
	if err := spec.ValidatePolicy(policy); err != nil {
		return nil, err
	}
	if policy.Spec.ExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, policy.Spec.ExpiresAt)
		if err != nil || !time.Now().Before(expiry) {
			return nil, spec.Err(12, "trust policy has expired or invalid expiry")
		}
	}
	root, err := os.MkdirTemp("", "cinderlock-verified-")
	if err != nil {
		return nil, err
	}
	v := &Verified{Root: root}
	complete := false
	defer func() {
		if !complete {
			_ = v.Close()
		}
	}()
	var indexBytes []byte
	var signatures []spec.Signature
	seen := map[string]bool{}
	total := int64(0)
	ingest := func(name string, size int64, r io.Reader) error {
		if !safeMember(name) || seen[name] || len(seen) >= MaxMembers {
			return spec.Err(12, "invalid, repeated, or excessive bundle member %q", name)
		}
		seen[name] = true
		if size < 0 || size > MaxPayloadBytes-total {
			return spec.Err(12, "bundle payload limit exceeded")
		}
		total += size
		switch {
		case name == IndexName:
			if size > MaxMetadataBytes {
				return spec.Err(12, "bundle index exceeds limit")
			}
			b, err := io.ReadAll(io.LimitReader(r, size+1))
			if err != nil {
				return err
			}
			if int64(len(b)) != size {
				return io.ErrUnexpectedEOF
			}
			indexBytes = b
			return writeExclusive(filepath.Join(root, name), b, 0600)
		case strings.HasPrefix(name, "signatures/"):
			keyID := strings.TrimSuffix(strings.TrimPrefix(name, "signatures/"), ".sig")
			if !strings.HasSuffix(name, ".sig") || !validKeyID(keyID) || size > 16384 || len(signatures) >= 256 {
				return spec.Err(12, "invalid signature member")
			}
			b, err := io.ReadAll(io.LimitReader(r, size+1))
			if err != nil {
				return err
			}
			if int64(len(b)) != size {
				return io.ErrUnexpectedEOF
			}
			var s spec.Signature
			if err := strictJSON(b, &s, true); err != nil {
				return spec.Err(12, "invalid signature: %v", err)
			}
			if s.KeyID != keyID {
				return spec.Err(12, "signature member/key ID mismatch")
			}
			signatures = append(signatures, s)
			if err := os.MkdirAll(filepath.Join(root, "signatures"), 0700); err != nil {
				return err
			}
			return writeExclusive(filepath.Join(root, filepath.FromSlash(name)), b, 0600)
		case strings.HasPrefix(name, "blobs/sha256/"):
			d := "sha256:" + strings.TrimPrefix(name, "blobs/sha256/")
			if !ValidDigest(d) {
				return spec.Err(12, "invalid payload path")
			}
			var stat unix.Statfs_t
			if err := unix.Statfs(root, &stat); err != nil {
				return err
			}
			free := uint64(stat.Bavail) * uint64(stat.Bsize)
			if uint64(size)+(32<<20) > free {
				return spec.Err(10, "insufficient space to stage bundle payload")
			}
			got, n, err := Store(ctx, root, io.LimitReader(r, size), max(size, 1))
			if err != nil {
				return err
			}
			if n != size || got != d {
				return spec.Err(12, "payload %s digest/size mismatch", name)
			}
			return nil
		default:
			return spec.Err(12, "unrecognized bundle member %q", name)
		}
	}
	info, err := os.Lstat(bundlePath)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		err = filepath.WalkDir(bundlePath, func(p string, entry fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if entry.IsDir() {
				return nil
			}
			i, e := entry.Info()
			if e != nil {
				return e
			}
			if !i.Mode().IsRegular() {
				return spec.Err(12, "bundle directory contains a link or non-regular member")
			}
			rel, e := filepath.Rel(bundlePath, p)
			if e != nil {
				return e
			}
			f, e := os.Open(p)
			if e != nil {
				return e
			}
			e = ingest(filepath.ToSlash(rel), i.Size(), f)
			f.Close()
			return e
		})
	} else {
		if !info.Mode().IsRegular() {
			return nil, spec.Err(12, "bundle must be a regular archive or directory")
		}
		f, e := os.Open(bundlePath)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		tr := tar.NewReader(&contextReader{ctx: ctx, r: f})
		for {
			h, e := tr.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				err = e
				break
			}
			if h.Typeflag != tar.TypeReg || len(h.PAXRecords) > 0 || len(h.Xattrs) > 0 || (h.Format != tar.FormatUSTAR && h.Format != tar.FormatGNU) {
				err = spec.Err(12, "unsupported archive member type/format")
				break
			}
			if e := ingest(h.Name, h.Size, tr); e != nil {
				err = e
				break
			}
		}
		if err == nil {
			extra := make([]byte, 1)
			n, e := f.Read(extra)
			if n != 0 || e != io.EOF {
				err = spec.Err(12, "trailing archive content")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if len(indexBytes) == 0 || len(signatures) == 0 {
		return nil, spec.Err(12, "bundle index and authorized signature are required")
	}
	if err := strictJSON(indexBytes, &v.Index, true); err != nil {
		return nil, spec.Err(12, "invalid bundle index: %v", err)
	}
	if err := validateIndex(v.Index); err != nil {
		return nil, err
	}
	app := v.Index.Lock.Release.Metadata.Application
	channel := v.Index.Lock.Release.Metadata.Channel
	authorized := false
	for _, s := range signatures {
		for _, k := range policy.Spec.Keys {
			if k.ID != s.KeyID || k.Revoked || !scope(k.Applications, app) || !scope(k.Channels, channel) || (len(k.Roles) > 0 && !scope(k.Roles, "release")) {
				continue
			}
			pub, e := ParsePublicKey(k.PublicKey)
			if e == nil && VerifySignature(indexBytes, s, pub) == nil {
				authorized = true
			}
		}
	}
	if !authorized {
		return nil, spec.Err(12, "no valid signature from an independently admitted release key")
	}
	if v.Index.Lock.Release.Metadata.Sequence < policy.Spec.MinSequence[app+"/"+channel] {
		return nil, spec.Err(12, "release sequence is below local policy floor")
	}
	expected := map[string]bool{IndexName: true}
	for name := range seen {
		if strings.HasPrefix(name, "signatures/") {
			expected[name] = true
		}
	}
	if v.Index.Inventory != nil {
		generated, err := Inventory(v.Index.Lock)
		if err != nil {
			return nil, err
		}
		expected, err := spec.Canonical(generated)
		if err != nil {
			return nil, err
		}
		actual, err := InventoryBytes(v)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(actual, expected) {
			return nil, spec.Err(12, "signed component inventory does not match locked artifacts and coverage")
		}
	}
	for _, d := range v.Index.Payloads {
		expected[d.Path] = true
		if !seen[d.Path] {
			return nil, spec.Err(12, "required payload %s is missing", d.Path)
		}
		if e := VerifyBlob(ctx, root, d.Digest, d.Size); e != nil {
			return nil, spec.Err(12, "payload verification failed: %v", e)
		}
	}
	for name := range seen {
		if !expected[name] {
			return nil, spec.Err(12, "unindexed member %s", name)
		}
	}
	for _, a := range v.Index.Lock.Assets {
		if a.Type == "image" {
			d := a.RootDescriptor
			graph, e := imageGraph(ctx, verifiedStorage{root}, ociSpec.Descriptor{Digest: digest.Digest(d.Digest), Size: d.Size, MediaType: d.MediaType})
			if e != nil {
				return nil, e
			}
			declared := map[string]int64{}
			for _, f := range a.Files {
				declared[f.Digest] = f.Size
			}
			if len(graph) != len(declared) {
				return nil, spec.Err(12, "image graph does not match locked inventory")
			}
			for _, f := range graph {
				if declared[f.Digest] != f.Size {
					return nil, spec.Err(12, "undeclared image graph child")
				}
			}
		}
	}
	v.Digest = spec.Hash(indexBytes)
	complete = true
	return v, nil
}

func validKeyID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func scope(values []string, wanted string) bool {
	for _, v := range values {
		if v == wanted || v == "*" {
			return true
		}
	}
	return false
}

func validateIndex(i spec.BundleIndex) error {
	if err := spec.ValidateHeader(i.Header, "BundleIndex"); err != nil {
		return err
	}
	if i.Domain != spec.BundleDomain {
		return spec.Err(12, "unsupported bundle domain")
	}
	if err := spec.ValidateHeader(i.Lock.Header, "ReleaseLock"); err != nil {
		return err
	}
	if err := spec.ValidateRelease(i.Lock.Release); err != nil {
		return err
	}
	if i.Metadata != i.Lock.Release.Metadata || i.Lock.Metadata != i.Lock.Release.Metadata {
		return spec.Err(12, "bundle identity metadata mismatch")
	}
	d, err := spec.Digest(i.Lock.Release)
	if err != nil || d != i.Lock.SourceDigest {
		return spec.Err(12, "release-source digest mismatch")
	}
	for _, c := range i.RequiredCapabilities {
		if c != "bundle.v1" && c != "oci.v1" && c != "inventory.v1" {
			return spec.Err(10, "unsupported bundle capability %s", c)
		}
	}
	if len(i.Payloads) > MaxMembers || len(i.Lock.Assets) > 100000 {
		return spec.Err(12, "bundle inventory exceeds limits")
	}
	payloads := map[string]spec.Descriptor{}
	var total int64
	for _, p := range i.Payloads {
		if !ValidDigest(p.Digest) || p.Path != "blobs/sha256/"+p.Digest[7:] || p.Size < 0 || p.Size > MaxPayloadBytes-total {
			return spec.Err(12, "invalid payload descriptor")
		}
		if _, ok := payloads[p.Digest]; ok {
			return spec.Err(12, "duplicate payload descriptor")
		}
		payloads[p.Digest] = p
		total += p.Size
	}
	ids := map[string]bool{}
	used := map[string]bool{}
	for _, a := range i.Lock.Assets {
		if a.ID == "" || ids[a.ID] || len(a.Files) == 0 || !ValidDigest(a.Digest) {
			return spec.Err(12, "invalid or duplicate locked asset")
		}
		ids[a.ID] = true
		paths := map[string]bool{}
		var size int64
		for _, f := range a.Files {
			p, ok := payloads[f.Digest]
			if a.Type == "image" && f.Path != p.Path {
				return spec.Err(12, "image inventory path does not match its descriptor")
			}
			if !ok || p.Size != f.Size || !safeMember(f.Path) || paths[f.Path] || (f.Mode != 0644 && f.Mode != 0755) {
				return spec.Err(12, "invalid locked asset file %s", f.Path)
			}
			paths[f.Path] = true
			used[f.Digest] = true
			size += f.Size
		}
		if size != a.Size {
			return spec.Err(12, "locked asset size mismatch")
		}
		if a.Type == "image" {
			if a.RootDescriptor == nil || a.RootDescriptor.Digest != a.Digest || !used[a.Digest] {
				return spec.Err(12, "image root descriptor missing")
			}
			p := payloads[a.Digest]
			if a.RootDescriptor.Size != p.Size || a.RootDescriptor.Path != p.Path {
				return spec.Err(12, "image root descriptor mismatch")
			}
		} else {
			tree, e := spec.Digest(a.Files)
			if e != nil {
				return e
			}
			if a.Digest != tree && (len(a.Files) != 1 || a.Digest != a.Files[0].Digest) {
				return spec.Err(12, "asset tree digest mismatch")
			}
		}
	}
	if i.Inventory != nil {
		d := i.Inventory
		p, ok := payloads[d.Digest]
		if !ok || *d != p || d.Size > MaxMetadataBytes || d.MediaType != "application/vnd.cyclonedx+json" {
			return spec.Err(12, "invalid inventory descriptor")
		}
		used[d.Digest] = true
	} else {
		for _, c := range i.RequiredCapabilities {
			if c == "inventory.v1" {
				return spec.Err(12, "required inventory is absent")
			}
		}
	}
	if !ids["cinderlock-chart"] {
		return spec.Err(12, "chart input missing from locked release")
	}
	for n := range i.Lock.Release.Spec.Deployment.Values {
		if !ids[fmt.Sprintf("cinderlock-values-%d", n)] {
			return spec.Err(12, "values input missing from locked release")
		}
	}
	for _, a := range i.Lock.Release.Spec.Assets {
		if !ids[a.ID] {
			return spec.Err(12, "declared asset %s missing from lock", a.ID)
		}
	}
	if len(used) != len(payloads) {
		return spec.Err(12, "unreferenced payload is not admitted")
	}
	return nil
}
