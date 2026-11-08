package intake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
)

const MaxManifestBytes = 8 << 20
const MaxAttachmentBytes int64 = 64 << 20
const MaxAttachments = 128

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Content struct {
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	MediaType string `json:"mediaType,omitempty"`
}
type Asset struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Digest   string `json:"digest"`
	Size     int64  `json:"size"`
	Files    int64  `json:"files"`
	Platform string `json:"platform,omitempty"`
}
type LicenseNotice struct {
	AssetID string `json:"assetID"`
	License string `json:"declaredLicense"`
}
type Prerequisites struct {
	Deployment           string   `json:"deployment"`
	RequiredCapabilities []string `json:"requiredCapabilities"`
	MinFreeBytes         int64    `json:"minFreeBytes"`
	GPUModels            []string `json:"gpuModels"`
	GPUCount             int64    `json:"gpuCount"`
	MinGPUMemoryMiB      int64    `json:"minGPUMemoryMiB"`
	DriverVersions       []string `json:"driverVersions"`
	Precision            string   `json:"precision,omitempty"`
	LicenseMode          string   `json:"licenseMode,omitempty"`
	RequiredChecks       []string `json:"requiredChecks"`
	Coverage             string   `json:"coverage"`
}
type ToolchainCoverage struct {
	DeclarationDigest string   `json:"declarationDigest"`
	RecordedFields    []string `json:"recordedFields"`
	HelmDigest        string   `json:"helmDigest,omitempty"`
	Reproduction      string   `json:"reproduction"`
	Coverage          string   `json:"coverage"`
}

// Attachment describes bytes and declared producer metadata, never a scan result.
type Attachment struct {
	Digest   string `json:"digest"`
	Size     int64  `json:"size"`
	Producer string `json:"producer"`
	Version  string `json:"producerVersion"`
	Kind     string `json:"kind"`
}
type ManifestOptions struct {
	NoticeAssets []string
	Attachments  []Attachment
}
type Manifest struct {
	spec.Header
	BundleDigest       string            `json:"bundleDigest"`
	ReleaseDigest      string            `json:"releaseDigest"`
	LockDigest         string            `json:"lockDigest"`
	Profile            string            `json:"profile"`
	Payloads           []Content         `json:"payloads"`
	TotalPayloadBytes  int64             `json:"totalPayloadBytes"`
	Assets             []Asset           `json:"assets"`
	Inventory          *Content          `json:"inventory,omitempty"`
	InventoryCoverage  string            `json:"inventoryCoverage"`
	Licenses           []LicenseNotice   `json:"licenses"`
	NoticeAssets       []string          `json:"noticeAssets"`
	NoticesCoverage    string            `json:"noticesCoverage"`
	Prerequisites      Prerequisites     `json:"prerequisites"`
	Toolchain          ToolchainCoverage `json:"toolchain"`
	Attachments        []Attachment      `json:"attachments"`
	AttachmentCoverage string            `json:"attachmentCoverage"`
	Limitations        []string          `json:"limitations"`
}

func CreateManifest(ctx context.Context, path string, policy spec.TrustPolicy, options ManifestOptions) (Manifest, error) {
	verified, err := bundle.Verify(ctx, path, policy)
	if err != nil {
		return Manifest{}, err
	}
	defer verified.Close()
	index := verified.Index
	m := Manifest{Header: spec.NewHeader("IntakeManifest"), BundleDigest: verified.Digest, Profile: index.Lock.Release.Spec.Profile, Payloads: []Content{}, Assets: []Asset{}, Licenses: []LicenseNotice{}, NoticeAssets: append([]string{}, options.NoticeAssets...), Attachments: append([]Attachment{}, options.Attachments...), InventoryCoverage: "signed_declared_artifacts_only", NoticesCoverage: "vendor_labels_and_custodian_selection_only", AttachmentCoverage: "descriptor_only_execution_unverified", Limitations: []string{"physical_transfer_and_human_identity_unobserved", "deployment_hardware_workflows_recovery_and_entitlement_unqualified", "transport_bytes_source_paths_commands_and_site_credentials_omitted", "declared_runtime_tools_and_platform_external_unless_supplied"}}
	m.Metadata = index.Lock.Release.Metadata
	m.ReleaseDigest, err = spec.Digest(index.Lock.Release)
	if err != nil {
		return m, err
	}
	m.LockDigest, err = spec.Digest(index.Lock)
	if err != nil {
		return m, err
	}
	for _, p := range index.Payloads {
		if p.Size < 0 || p.Size > bundle.MaxPayloadBytes-m.TotalPayloadBytes {
			return m, errors.New("intake payload sizes exceed bounds")
		}
		m.TotalPayloadBytes += p.Size
		m.Payloads = append(m.Payloads, Content{Digest: p.Digest, Size: p.Size, MediaType: p.MediaType})
	}
	ids := map[string]bool{}
	for _, a := range index.Lock.Assets {
		var size int64
		for _, f := range a.Files {
			if f.Size < 0 || f.Size > bundle.MaxPayloadBytes-size {
				return m, errors.New("intake asset sizes exceed bounds")
			}
			size += f.Size
		}
		if size != a.Size {
			return m, errors.New("intake asset size mismatch")
		}
		ids[a.ID] = true
		m.Assets = append(m.Assets, Asset{ID: a.ID, Type: a.Type, Digest: a.Digest, Size: a.Size, Files: int64(len(a.Files)), Platform: a.Platform})
		m.Licenses = append(m.Licenses, LicenseNotice{AssetID: a.ID, License: a.License})
	}
	if index.Inventory != nil {
		m.Inventory = &Content{Digest: index.Inventory.Digest, Size: index.Inventory.Size, MediaType: index.Inventory.MediaType}
	} else {
		m.InventoryCoverage = "not_supplied"
	}
	seen := map[string]bool{}
	for _, id := range m.NoticeAssets {
		if !ids[id] || seen[id] {
			return m, errors.New("notice selection must reference distinct bundled assets")
		}
		seen[id] = true
	}
	release := index.Lock.Release.Spec
	m.Prerequisites = Prerequisites{Deployment: release.Deployment.Type, RequiredCapabilities: append([]string{}, index.RequiredCapabilities...), MinFreeBytes: release.MinFreeBytes, GPUModels: append([]string{}, release.AIProfile.GPUModels...), GPUCount: release.AIProfile.GPUCount, MinGPUMemoryMiB: release.AIProfile.MinGPUMemoryMiB, DriverVersions: append([]string{}, release.AIProfile.DriverVersions...), Precision: release.AIProfile.Precision, RequiredChecks: append([]string{}, release.RequiredChecks...), Coverage: "signed_declared_profile_fields_only"}
	if release.License != nil {
		m.Prerequisites.LicenseMode = release.License.Mode
	}
	toolchain := index.Lock.Toolchain
	m.Toolchain.DeclarationDigest, err = spec.Digest(toolchain)
	if err != nil {
		return m, err
	}
	m.Toolchain.RecordedFields = []string{}
	for _, entry := range []struct{ name, value string }{{"go", toolchain.Go}, {"cli", toolchain.CLI}, {"helm", toolchain.Helm}, {"helmDigest", toolchain.HelmDigest}} {
		if entry.value != "" {
			m.Toolchain.RecordedFields = append(m.Toolchain.RecordedFields, entry.name)
		}
	}
	if toolchain.HelmDigest != "" {
		if !spec.ValidDigest(toolchain.HelmDigest) {
			return m, errors.New("invalid declared Helm digest")
		}
		m.Toolchain.HelmDigest = toolchain.HelmDigest
	}
	m.Toolchain.Reproduction = "not_tested"
	m.Toolchain.Coverage = "producer_declaration_digest_only"
	sort.Slice(m.Payloads, func(i, j int) bool { return m.Payloads[i].Digest < m.Payloads[j].Digest })
	sort.Slice(m.Assets, func(i, j int) bool { return m.Assets[i].ID < m.Assets[j].ID })
	sort.Slice(m.Licenses, func(i, j int) bool { return m.Licenses[i].AssetID < m.Licenses[j].AssetID })
	sort.Strings(m.NoticeAssets)
	sort.Slice(m.Attachments, func(i, j int) bool {
		a, b := m.Attachments[i], m.Attachments[j]
		if a.Digest != b.Digest {
			return a.Digest < b.Digest
		}
		if a.Producer != b.Producer {
			return a.Producer < b.Producer
		}
		return a.Version < b.Version
	})
	return m, ValidateManifest(m)
}

func ValidateManifest(m Manifest) error {
	if err := spec.ValidateHeader(m.Header, "IntakeManifest"); err != nil {
		return err
	}
	if m.Metadata.Application == "" || m.Metadata.Version == "" || m.Profile == "" || !spec.ValidDigest(m.BundleDigest) || !spec.ValidDigest(m.ReleaseDigest) || !spec.ValidDigest(m.LockDigest) || !spec.ValidDigest(m.Toolchain.DeclarationDigest) {
		return errors.New("intake manifest identity is incomplete")
	}
	if len(m.Payloads) == 0 || len(m.Payloads) > bundle.MaxMembers || len(m.Assets) == 0 || len(m.Assets) > 100000 || len(m.Attachments) > MaxAttachments {
		return errors.New("intake manifest counts exceed bounds")
	}
	var total int64
	seen := map[string]bool{}
	for _, p := range m.Payloads {
		if !spec.ValidDigest(p.Digest) || seen[p.Digest] || p.Size < 0 || p.Size > bundle.MaxPayloadBytes-total {
			return errors.New("invalid intake content size or digest")
		}
		seen[p.Digest] = true
		total += p.Size
	}
	if total != m.TotalPayloadBytes {
		return errors.New("intake total payload size mismatch")
	}
	ids := map[string]bool{}
	for _, a := range m.Assets {
		if !identifier.MatchString(a.ID) || ids[a.ID] || !spec.ValidDigest(a.Digest) || a.Size < 0 || a.Size > bundle.MaxPayloadBytes || a.Files <= 0 || a.Files > bundle.MaxMembers {
			return errors.New("invalid intake asset")
		}
		ids[a.ID] = true
	}
	if len(m.NoticeAssets) > len(m.Assets) || len(m.Licenses) != len(m.Assets) {
		return errors.New("intake notices do not match assets")
	}
	seen = map[string]bool{}
	for _, id := range m.NoticeAssets {
		if !ids[id] || seen[id] {
			return errors.New("invalid intake notice asset")
		}
		seen[id] = true
	}
	attachmentSizes := map[string]int64{}
	attachmentClaims := map[string]bool{}
	for _, a := range m.Attachments {
		if !spec.ValidDigest(a.Digest) || a.Size < 0 || a.Size > MaxAttachmentBytes || !identifier.MatchString(a.Producer) || !identifier.MatchString(a.Version) || a.Kind != "scanner-report" {
			return errors.New("invalid scanner attachment descriptor")
		}
		if size, exists := attachmentSizes[a.Digest]; exists && size != a.Size {
			return errors.New("scanner attachment digest has conflicting sizes")
		}
		attachmentSizes[a.Digest] = a.Size
		claim := a.Digest + "/" + a.Producer + "/" + a.Version
		if attachmentClaims[claim] {
			return errors.New("duplicate scanner attachment descriptor")
		}
		attachmentClaims[claim] = true
	}
	body, err := spec.Canonical(m)
	if err != nil {
		return err
	}
	if len(body) > MaxManifestBytes {
		return errors.New("intake manifest exceeds metadata limit")
	}
	return nil
}

func VerifyManifest(ctx context.Context, path string, policy spec.TrustPolicy, m Manifest) error {
	if err := ValidateManifest(m); err != nil {
		return spec.Err(12, "invalid intake manifest: %v", err)
	}
	current, err := CreateManifest(ctx, path, policy, ManifestOptions{NoticeAssets: m.NoticeAssets, Attachments: m.Attachments})
	if err != nil {
		return err
	}
	expected, err := spec.Canonical(current)
	if err != nil {
		return err
	}
	actual, err := spec.Canonical(m)
	if err != nil {
		return err
	}
	if !bytes.Equal(expected, actual) {
		return spec.Err(12, "intake manifest does not match the verified bundle and declared options")
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func AttachmentForFile(ctx context.Context, path, producer, version string) (Attachment, error) {
	out := Attachment{Producer: producer, Version: version, Kind: "scanner-report"}
	if !identifier.MatchString(producer) || !identifier.MatchString(version) {
		return out, errors.New("attachment producer and version must be bounded labels")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return out, errors.New("cannot open scanner attachment")
	}
	f := os.NewFile(uintptr(fd), "")
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > MaxAttachmentBytes {
		return out, errors.New("scanner attachment must be a bounded regular file")
	}
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, io.LimitReader(f, MaxAttachmentBytes+1)})
	if err != nil {
		return out, err
	}
	after, err := f.Stat()
	if err != nil || n != before.Size() || n > MaxAttachmentBytes || !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		return out, errors.New("scanner attachment changed during hashing")
	}
	out.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	out.Size = n
	return out, nil
}
