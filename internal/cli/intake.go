package cli

import (
	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/intake"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/spf13/cobra"
)

func addIntake(root *cobra.Command, o *options) {
	bundles, _, _ := root.Find([]string{"bundle"})
	var trust, out, producer, version string
	var notices, attachments []string
	manifest := &cobra.Command{Use: "intake-manifest BUNDLE", Short: "Verify a bundle and list its exact intake identities, content and declared prerequisites", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		policy, err := loadPolicy(trust)
		if err != nil {
			return err
		}
		options := intake.ManifestOptions{NoticeAssets: notices}
		if len(attachments) > intake.MaxAttachments {
			return spec.Err(2, "scanner attachment count exceeds bounds")
		}
		if len(attachments) > 0 && (producer == "" || version == "") {
			return spec.Err(2, "scanner attachment producer and version are required")
		}
		for _, path := range attachments {
			a, err := intake.AttachmentForFile(ctx, path, producer, version)
			if err != nil {
				if ctx.Err() != nil {
					return spec.Err(17, "intake attachment hashing interrupted")
				}
				return err
			}
			options.Attachments = append(options.Attachments, a)
		}
		result, err := intake.CreateManifest(ctx, args[0], policy, options)
		if err != nil {
			if ctx.Err() != nil {
				return spec.Err(17, "intake bundle verification interrupted")
			}
			return err
		}
		if err = spec.Write(out, result); err != nil {
			return err
		}
		digest, err := spec.Digest(result)
		if err != nil {
			return err
		}
		return o.emit(map[string]any{"path": out, "manifestDigest": digest, "bundleDigest": result.BundleDigest, "scope": "verified intake metadata; no deployment or scan performed"})
	}}
	manifest.Flags().StringVar(&trust, "trust", "", "Current independently admitted release trust policy")
	manifest.Flags().StringVar(&out, "out", "", "New private intake manifest path")
	manifest.Flags().StringArrayVar(&notices, "notice-asset", nil, "Explicit bundled asset ID selected as notice material; repeatable")
	manifest.Flags().StringArrayVar(&attachments, "scanner-attachment", nil, "Local report to hash only; never executes or interprets a scanner")
	manifest.Flags().StringVar(&producer, "scanner-producer", "", "Custodian-declared scanner attachment producer")
	manifest.Flags().StringVar(&version, "scanner-version", "", "Custodian-declared scanner attachment version")
	_ = manifest.MarkFlagRequired("trust")
	_ = manifest.MarkFlagRequired("out")
	bundles.AddCommand(manifest)

	group := &cobra.Command{Use: "intake", Short: "Record scoped local custody declarations without asserting physical transfer or approval"}
	root.AddCommand(group)
	var manifestPath, bundlePath, vendorTrust, keys, previous string
	var private, keyID, custodian, site, expiry, receiptOut string
	var sequence int64
	sign := &cobra.Command{Use: "sign-receipt", Short: "Sign exact manifest bytes using a separately admitted customer custody key", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		var m intake.Manifest
		var policy intake.CustodyPolicy
		if err := read(manifestPath, &m); err != nil {
			return err
		}
		if err := read(keys, &policy); err != nil {
			return err
		}
		vendor, err := loadPolicy(vendorTrust)
		if err != nil {
			return err
		}
		key, err := bundle.ReadPrivateKey(private)
		if err != nil {
			return err
		}
		receipt, err := intake.SignReceipt(ctx, bundlePath, vendor, m, policy, intake.Claim{Custodian: custodian, Site: site, Sequence: sequence, ExpiresAt: expiry}, previous, keyID, key, nil)
		if err != nil {
			if ctx.Err() != nil {
				return spec.Err(17, "intake receipt signing interrupted")
			}
			if spec.ExitCode(err) != 19 {
				return err
			}
			return spec.Err(16, "custody receipt not signed: %v", err)
		}
		if err = spec.Write(receiptOut, receipt); err != nil {
			return err
		}
		digest, err := spec.Digest(receipt)
		if err != nil {
			return err
		}
		return o.emit(map[string]any{"path": receiptOut, "receiptDigest": digest, "previousDigest": previous, "physicalCustody": "not_observed", "approval": "not_attested", "executionAuthority": "none"})
	}}
	sign.Flags().StringVar(&manifestPath, "manifest", "", "Exact intake manifest")
	sign.Flags().StringVar(&bundlePath, "bundle", "", "Bundle to reverify against the manifest")
	sign.Flags().StringVar(&vendorTrust, "trust", "", "Current release trust policy")
	sign.Flags().StringVar(&keys, "keys", "", "Independent customer CustodyPolicy")
	sign.Flags().StringVar(&previous, "previous-head", "", "Trusted previous receipt digest, or explicit genesis")
	sign.Flags().StringVar(&private, "key", "", "Private Ed25519 PKCS8 key; mode 0600 or 0400")
	sign.Flags().StringVar(&keyID, "key-id", "", "Independently admitted customer custody key ID")
	sign.Flags().StringVar(&custodian, "custodian", "", "Declared bounded custodian label, not a verified personal identity")
	sign.Flags().StringVar(&site, "site", "", "Declared bounded site label, not an observed physical location")
	sign.Flags().StringVar(&expiry, "expires", "", "Explicit RFC3339 receipt expiry covered by the custody key")
	sign.Flags().Int64Var(&sequence, "sequence", 1, "Chain position; genesis is 1, subsequent positions advance the anchored head")
	sign.Flags().StringVar(&receiptOut, "out", "", "New private receipt path")
	for _, flag := range []string{"manifest", "bundle", "trust", "keys", "previous-head", "key", "key-id", "custodian", "site", "expires", "out"} {
		_ = sign.MarkFlagRequired(flag)
	}
	group.AddCommand(sign)

	var verifyManifest, verifyBundle, verifyTrust, verifyKeys, verifyPrevious, headFile string
	verify := &cobra.Command{Use: "verify-receipt RECEIPT", Short: "Reverify the bundle, manifest, custody key scope and exact previous head", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		var m intake.Manifest
		var policy intake.CustodyPolicy
		var receipt intake.SignedReceipt
		if err := read(verifyManifest, &m); err != nil {
			return err
		}
		if err := read(verifyKeys, &policy); err != nil {
			return err
		}
		if err := read(args[0], &receipt); err != nil {
			return err
		}
		vendor, err := loadPolicy(verifyTrust)
		if err != nil {
			return err
		}
		var result intake.Verification
		if headFile != "" {
			result, err = intake.AnchorReceipt(ctx, headFile, verifyBundle, vendor, m, receipt, policy, verifyPrevious, nil)
		} else {
			result, err = intake.VerifyReceipt(ctx, verifyBundle, vendor, m, receipt, policy, verifyPrevious, nil)
		}
		if err != nil {
			if ctx.Err() != nil {
				return spec.Err(17, "custody verification interrupted; inspect any local head before retrying")
			}
			return spec.Err(12, "custody receipt rejected: %v", err)
		}
		return o.emit(result)
	}}
	verify.Flags().StringVar(&verifyManifest, "manifest", "", "Exact intake manifest")
	verify.Flags().StringVar(&verifyBundle, "bundle", "", "Bundle to reverify against the manifest")
	verify.Flags().StringVar(&verifyTrust, "trust", "", "Current release trust policy")
	verify.Flags().StringVar(&verifyKeys, "keys", "", "Current independently admitted customer CustodyPolicy")
	verify.Flags().StringVar(&verifyPrevious, "previous-head", "", "Trusted previous receipt digest, or explicit genesis")
	verify.Flags().StringVar(&headFile, "head-file", "", "Optional private local compare-and-swap head; advances only after full verification")
	for _, flag := range []string{"manifest", "bundle", "trust", "keys", "previous-head"} {
		_ = verify.MarkFlagRequired(flag)
	}
	group.AddCommand(verify)
}
