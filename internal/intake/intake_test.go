package intake_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/intake"
	"github.com/cenab/cinderlock/internal/spec"
)

type fixture struct {
	dir, cache, path, releasePath, private string
	vendor                                 spec.TrustPolicy
	custody                                intake.CustodyPolicy
	key                                    ed25519.PrivateKey
	release                                spec.Release
	now                                    time.Time
	manifest                               intake.Manifest
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	f := fixture{dir: t.TempDir(), now: time.Now().UTC()}
	f.cache = filepath.Join(f.dir, "cache")
	f.private = filepath.Join(f.dir, "vendor.key")
	public := filepath.Join(f.dir, "vendor.pub")
	if err := bundle.GenerateKey(f.private, public); err != nil {
		t.Fatal(err)
	}
	vendorKey, err := bundle.ReadPrivateKey(f.private)
	if err != nil {
		t.Fatal(err)
	}
	f.vendor = spec.TrustPolicy{Header: spec.NewHeader("TrustPolicy"), Spec: spec.TrustSpec{Epoch: 1, Keys: []spec.TrustedKey{{ID: "release", PublicKey: base64.StdEncoding.EncodeToString(vendorKey.Public().(ed25519.PublicKey)), Applications: []string{"intake-fixture"}, Channels: []string{"stable"}, Roles: []string{"release"}}}}}
	if err = os.Mkdir(filepath.Join(f.dir, "PRIVATE-SOURCE-MARKER"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{"chart.tgz": "transport-only fixture, not a deployable Helm chart", "NOTICE.txt": "synthetic notice", "PRIVATE-SOURCE-MARKER/weights.bin": "synthetic weights"} {
		if err = os.WriteFile(filepath.Join(f.dir, path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := spec.Release{Header: spec.NewHeader("Release"), Spec: spec.ReleaseSpec{Profile: "lab", Deployment: spec.Deployment{Type: "helm", Chart: "chart.tgz"}, Assets: []spec.Asset{{ID: "model", Type: "model-tree", Source: "PRIVATE-SOURCE-MARKER", License: "Apache-2.0"}, {ID: "notice", Type: "file", Source: "NOTICE.txt", License: "Apache-2.0"}}, Operations: []spec.Operation{{ID: "deploy", Type: "helm", Idempotent: true}}, Checks: []spec.Check{{ID: "query", Type: "http", Domain: "workflow", Required: true, URL: "http://internal-api/PRIVATE-ENDPOINT-MARKER", ExpectedStatus: 200}}, RequiredChecks: []string{"query"}, Transitions: []spec.Transition{{ID: "from-one", FromRelease: "1", Operations: []string{"deploy"}, Recovery: "old"}}, Recovery: []spec.Recovery{{ID: "old", ToRelease: "1", Operations: []spec.Operation{{ID: "restore", Type: "helm", Idempotent: true}}}}}}
	r.Metadata = spec.Metadata{Application: "intake-fixture", Version: "2", Channel: "stable", Sequence: 2}
	f.release = r
	f.releasePath = filepath.Join(f.dir, "release.json")
	if err = spec.Write(f.releasePath, r); err != nil {
		t.Fatal(err)
	}
	locked, err := bundle.Lock(ctx, f.releasePath, f.cache)
	if err != nil {
		t.Fatal(err)
	}
	locked.Toolchain.Helm = "/PRIVATE-TOOLCHAIN-MARKER/helm"
	f.path = filepath.Join(f.dir, "release.cinder")
	if err = bundle.Build(ctx, locked, f.cache, f.path, f.private, "release"); err != nil {
		t.Fatal(err)
	}
	customerPrivate := filepath.Join(f.dir, "customer.key")
	if err = bundle.GenerateKey(customerPrivate, filepath.Join(f.dir, "customer.pub")); err != nil {
		t.Fatal(err)
	}
	f.key, err = bundle.ReadPrivateKey(customerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	f.custody = intake.CustodyPolicy{Header: spec.NewHeader("CustodyPolicy"), Keys: []intake.CustodyKey{{ID: "customer", PublicKey: base64.StdEncoding.EncodeToString(f.key.Public().(ed25519.PublicKey)), Custodians: []string{"receiving-team", "inspection-team"}, Sites: []string{"offline-lab"}, Applications: []string{"intake-fixture"}, Profiles: []string{"lab"}, NotBefore: f.now.Add(-time.Hour).Format(time.RFC3339Nano), ExpiresAt: f.now.Add(48 * time.Hour).Format(time.RFC3339Nano)}}}
	f.manifest, err = intake.CreateManifest(ctx, f.path, f.vendor, intake.ManifestOptions{NoticeAssets: []string{"notice"}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) sign(t *testing.T, previous string, sequence int64, custodian string) intake.SignedReceipt {
	t.Helper()
	r, err := intake.SignReceipt(context.Background(), f.path, f.vendor, f.manifest, f.custody, intake.Claim{Custodian: custodian, Site: "offline-lab", Sequence: sequence, ExpiresAt: f.now.Add(24 * time.Hour).Format(time.RFC3339Nano)}, previous, "customer", f.key, fixedClock(f.now))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestManifestVerifiesExactBundleWithoutSourcePathsOrScanClaims(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	m := f.manifest
	if m.Metadata.Application != "intake-fixture" || m.Profile != "lab" || m.Inventory == nil || m.Inventory.MediaType != "application/vnd.cyclonedx+json" {
		t.Fatal("missing exact content/profile/inventory", m)
	}
	data, err := spec.Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{f.dir, "PRIVATE-SOURCE-MARKER", "PRIVATE-ENDPOINT-MARKER", "PRIVATE-TOOLCHAIN-MARKER", "weights.bin"} {
		if strings.Contains(string(data), private) {
			t.Fatal("manifest exposed source or toolchain detail", private)
		}
	}
	var total int64
	for _, p := range m.Payloads {
		total += p.Size
	}
	if total != m.TotalPayloadBytes {
		t.Fatal("payload total differs from exact inventory")
	}
	if err = intake.VerifyManifest(ctx, f.path, f.vendor, m); err != nil {
		t.Fatal(err)
	}
	changed := m
	changed.BundleDigest = spec.Hash([]byte("wrong bundle"))
	if err = intake.VerifyManifest(ctx, f.path, f.vendor, changed); err == nil {
		t.Fatal("wrong bundle identity accepted")
	}
	changed = m
	changed.Prerequisites.MinFreeBytes++
	if err = intake.VerifyManifest(ctx, f.path, f.vendor, changed); err == nil {
		t.Fatal("invented prerequisite accepted")
	}
	report := filepath.Join(f.dir, "PRIVATE-REPORT-PATH.json")
	reportBytes := []byte(`{"secret":"PRIVATE-REPORT-CONTENT","claimedClean":true}`)
	if err = os.WriteFile(report, reportBytes, 0600); err != nil {
		t.Fatal(err)
	}
	attachment, err := intake.AttachmentForFile(ctx, report, "scanner-fixture", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if attachment.Digest != spec.Hash(reportBytes) || attachment.Size != int64(len(reportBytes)) {
		t.Fatal("attachment hash does not identify actual bytes")
	}
	attached, err := intake.CreateManifest(ctx, f.path, f.vendor, intake.ManifestOptions{Attachments: []intake.Attachment{attachment}})
	if err != nil {
		t.Fatal(err)
	}
	data, err = spec.Canonical(attached)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "PRIVATE-REPORT") || strings.Contains(string(data), "claimedClean") {
		t.Fatal("attachment contents or filename leaked")
	}
}

func TestReceiptBindsIndependentCustomerKeyExactManifestHeadAndTime(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	receipt := f.sign(t, intake.Genesis, 1, "receiving-team")
	verified, err := intake.VerifyReceipt(ctx, f.path, f.vendor, f.manifest, receipt, f.custody, intake.Genesis, fixedClock(f.now))
	if err != nil || verified.Anchored || verified.PhysicalCustody != "not_observed" || verified.Approval != "not_attested" || verified.ExecutionAuthority != "none" {
		t.Fatal("receipt strengthened scope or failed verification", err, verified)
	}
	if _, err = intake.VerifyReceipt(ctx, f.path, f.vendor, f.manifest, receipt, f.custody, spec.Hash([]byte("wrong head")), fixedClock(f.now)); err == nil {
		t.Fatal("wrong caller anchor accepted")
	}
	if _, err = intake.VerifyReceipt(ctx, f.path, f.vendor, f.manifest, receipt, f.custody, intake.Genesis, fixedClock(f.now.Add(25*time.Hour))); err == nil {
		t.Fatal("expired receipt accepted")
	}
	changed := receipt
	changed.Body = append([]byte(nil), receipt.Body...)
	changed.Body = []byte(strings.Replace(string(changed.Body), "receiving-team", "inspection-team", 1))
	if _, err = intake.VerifyReceipt(ctx, f.path, f.vendor, f.manifest, changed, f.custody, intake.Genesis, fixedClock(f.now)); err == nil {
		t.Fatal("tampered signature accepted")
	}
	changed = receipt
	changed.Signature.KeyID = "unknown"
	if _, err = intake.VerifyReceipt(ctx, f.path, f.vendor, f.manifest, changed, f.custody, intake.Genesis, fixedClock(f.now)); err == nil {
		t.Fatal("wrong issuer accepted")
	}
	policy := f.custody
	policy.Keys = append([]intake.CustodyKey(nil), policy.Keys...)
	policy.Keys[0].Revoked = true
	if _, err = intake.VerifyReceipt(ctx, f.path, f.vendor, f.manifest, receipt, policy, intake.Genesis, fixedClock(f.now)); err == nil {
		t.Fatal("revoked customer key accepted")
	}
	policy.Keys[0].Revoked = false
	policy.Keys[0].ExpiresAt = f.now.Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err = intake.VerifyReceipt(ctx, f.path, f.vendor, f.manifest, receipt, policy, intake.Genesis, fixedClock(f.now)); err == nil {
		t.Fatal("expired customer key scope accepted")
	}
	policy.Keys[0] = f.custody.Keys[0]
	policy.Keys[0].Profiles = []string{"other"}
	if _, err = intake.VerifyReceipt(ctx, f.path, f.vendor, f.manifest, receipt, policy, intake.Genesis, fixedClock(f.now)); err == nil {
		t.Fatal("cross-profile issuer accepted")
	}
	releaseKey, err := bundle.ReadPrivateKey(f.private)
	if err != nil {
		t.Fatal(err)
	}
	policy.Keys[0] = f.custody.Keys[0]
	policy.Keys[0].PublicKey = f.vendor.Spec.Keys[0].PublicKey
	if _, err = intake.SignReceipt(ctx, f.path, f.vendor, f.manifest, policy, intake.Claim{Custodian: "receiving-team", Site: "offline-lab", Sequence: 1, ExpiresAt: f.now.Add(time.Hour).Format(time.RFC3339Nano)}, intake.Genesis, "customer", releaseKey, fixedClock(f.now)); err == nil {
		t.Fatal("release key reused as independent customer authority")
	}
	changed = receipt
	changed.Signature, err = bundle.Sign(receipt.Body, "customer", f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = intake.VerifyReceipt(ctx, f.path, f.vendor, f.manifest, changed, f.custody, intake.Genesis, fixedClock(f.now)); err == nil {
		t.Fatal("release-domain signature accepted as custody receipt")
	}
	var body intake.ReceiptBody
	if err = spec.Decode(receipt.Body, &body); err != nil {
		t.Fatal(err)
	}
	body.PhysicalCustody = "observed"
	data, err := spec.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	changed = receipt
	changed.Body = data
	changed.Signature.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(f.key, append([]byte(intake.ReceiptDomain+"\x00"), data...)))
	if _, err = intake.VerifyReceipt(ctx, f.path, f.vendor, f.manifest, changed, f.custody, intake.Genesis, fixedClock(f.now)); err == nil {
		t.Fatal("valid signature allowed an unsupported physical custody claim")
	}
}

func TestAnchoredReceiptAdvancesOneHeadAndRejectsConcurrentForks(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	receipts := []intake.SignedReceipt{f.sign(t, intake.Genesis, 1, "receiving-team"), f.sign(t, intake.Genesis, 1, "inspection-team")}
	head := filepath.Join(t.TempDir(), "head.json")
	var wg sync.WaitGroup
	results := make(chan intake.Verification, 2)
	for _, receipt := range receipts {
		wg.Add(1)
		go func(r intake.SignedReceipt) {
			defer wg.Done()
			v, err := intake.AnchorReceipt(ctx, head, f.path, f.vendor, f.manifest, r, f.custody, intake.Genesis, func() time.Time { return f.now })
			if err == nil {
				results <- v
			}
		}(receipt)
	}
	wg.Wait()
	close(results)
	var accepted []intake.Verification
	for r := range results {
		accepted = append(accepted, r)
	}
	if len(accepted) != 1 || !accepted[0].Anchored {
		t.Fatal("concurrent fork was not rejected", accepted)
	}
	data, err := os.ReadFile(head)
	if err != nil {
		t.Fatal(err)
	}
	var stored intake.Head
	if err = spec.Decode(data, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.ReceiptDigest != accepted[0].ReceiptDigest || stored.Sequence != 1 || stored.ManifestDigest != accepted[0].ManifestDigest {
		t.Fatal("anchored head lost exact receipt identity", stored)
	}
	info, err := os.Stat(head)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("head is not private", err)
	}
	for _, r := range receipts {
		if _, err = intake.AnchorReceipt(ctx, head, f.path, f.vendor, f.manifest, r, f.custody, intake.Genesis, func() time.Time { return f.now }); err == nil {
			t.Fatal("old anchor replay accepted")
		}
	}
	next := f.sign(t, stored.ReceiptDigest, 2, "receiving-team")
	v, err := intake.AnchorReceipt(ctx, head, f.path, f.vendor, f.manifest, next, f.custody, stored.ReceiptDigest, func() time.Time { return f.now })
	if err != nil || !v.Anchored || v.Sequence != 2 {
		t.Fatal("valid head continuation rejected", err)
	}
}

func TestReceiptRejectsAnotherTrustedBundleAndUnsafeLocalHead(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	receipt := f.sign(t, intake.Genesis, 1, "receiving-team")
	other := f.release
	other.Metadata.Version = "3"
	other.Metadata.Sequence = 3
	path := filepath.Join(f.dir, "release-three.json")
	if err := spec.Write(path, other); err != nil {
		t.Fatal(err)
	}
	locked, err := bundle.Lock(ctx, path, f.cache)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(f.dir, "release-three.cinder")
	if err = bundle.Build(ctx, locked, f.cache, archive, f.private, "release"); err != nil {
		t.Fatal(err)
	}
	if _, err = intake.VerifyReceipt(ctx, archive, f.vendor, f.manifest, receipt, f.custody, intake.Genesis, fixedClock(f.now)); err == nil {
		t.Fatal("a different correctly signed bundle inherited the receipt")
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err = os.WriteFile(victim, []byte("unrelated private file"), 0600); err != nil {
		t.Fatal(err)
	}
	head := filepath.Join(t.TempDir(), "head.json")
	if err = os.Symlink(victim, head); err != nil {
		t.Fatal(err)
	}
	if _, err = intake.AnchorReceipt(ctx, head, f.path, f.vendor, f.manifest, receipt, f.custody, intake.Genesis, func() time.Time { return f.now }); err == nil {
		t.Fatal("symlink custody head accepted")
	}
	content, err := os.ReadFile(victim)
	if err != nil || string(content) != "unrelated private file" {
		t.Fatal("unrelated symlink target changed", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	newHead := filepath.Join(t.TempDir(), "cancelled.json")
	if _, err = intake.AnchorReceipt(canceled, newHead, f.path, f.vendor, f.manifest, receipt, f.custody, intake.Genesis, func() time.Time { return f.now }); err == nil {
		t.Fatal("cancelled anchor advanced")
	}
	if _, err = os.Stat(newHead); !os.IsNotExist(err) {
		t.Fatal("cancelled operation created a head", err)
	}
}

func TestManifestAndAttachmentSizeBounds(t *testing.T) {
	f := newFixture(t)
	m := f.manifest
	m.Payloads = append([]intake.Content(nil), m.Payloads...)
	m.Payloads[0].Size = -1
	if err := intake.ValidateManifest(m); err == nil {
		t.Fatal("negative payload accepted")
	}
	m = f.manifest
	m.Payloads = append([]intake.Content(nil), m.Payloads...)
	m.Payloads[0].Size = bundle.MaxPayloadBytes
	m.Payloads[1].Size = 9223372036854775807
	if err := intake.ValidateManifest(m); err == nil {
		t.Fatal("overflowing payload sum accepted")
	}
	path := filepath.Join(f.dir, "oversized-report")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(intake.MaxAttachmentBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	if _, err = intake.AttachmentForFile(context.Background(), path, "scanner", "1"); err == nil {
		t.Fatal("oversized attachment accepted")
	}
}

func TestCustodySignatureEncodingIsCanonical(t *testing.T) {
	f := newFixture(t)
	receipt := f.sign(t, intake.Genesis, 1, "receiving-team")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	text := []byte(receipt.Signature.Signature)
	index := len(text) - 3
	value := strings.IndexByte(alphabet, text[index])
	if value < 0 {
		t.Fatal("invalid fixture signature encoding")
	}
	text[index] = alphabet[value|1]
	// Standard base64 decoding tolerates altered unused padding bits. A receipt
	// identity must not acquire aliases without a newly signed declaration.
	original, err := base64.StdEncoding.DecodeString(receipt.Signature.Signature)
	if err != nil {
		t.Fatal(err)
	}
	aliased, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil || string(original) != string(aliased) {
		t.Fatal("fixture did not preserve signature bytes", err)
	}
	receipt.Signature.Signature = string(text)
	if _, err = intake.VerifyReceipt(context.Background(), f.path, f.vendor, f.manifest, receipt, f.custody, intake.Genesis, fixedClock(f.now)); err == nil {
		t.Fatal("noncanonical signature encoding created a receipt identity alias")
	}
}

func fixedClock(value time.Time) func() time.Time { return func() time.Time { return value } }

func TestCurrentTrustExpiryIsRecheckedAfterBundleVerification(t *testing.T) {
	f := newFixture(t)
	f.vendor.Spec.ExpiresAt = f.now.Add(time.Hour).Format(time.RFC3339Nano)
	receipt := f.sign(t, intake.Genesis, 1, "receiving-team")
	// A large offline bundle can take long enough to hash that the supplied
	// release trust expires after its initial validation. The decision clock
	// represents that later point; the receipt and customer key remain valid.
	if _, err := intake.VerifyReceipt(context.Background(), f.path, f.vendor, f.manifest, receipt, f.custody, intake.Genesis, fixedClock(f.now.Add(2*time.Hour))); err == nil {
		t.Fatal("expired release trust was accepted at the final custody verification decision")
	}
}
