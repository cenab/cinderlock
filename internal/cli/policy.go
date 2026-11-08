package cli

import (
	"errors"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/engine"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	"github.com/cenab/cinderlock/internal/trustupdate"
	"github.com/spf13/cobra"
)

func addPolicyAdmission(root *cobra.Command, o *options) {
	trust, _, _ := root.Find([]string{"trust"})
	var site, approved string
	admit := &cobra.Command{Use: "admit-policy", Short: "Preview or explicitly enroll an independently approved policy for the actual target", RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, policy, err := o.site(site)
		if err != nil {
			return err
		}
		store, err := o.store()
		if err != nil {
			return err
		}
		defer store.Close()
		eng, err := engine.New(s, store)
		if err != nil {
			return err
		}
		target, err := eng.TargetIdentity(ctx)
		if err != nil {
			return err
		}
		digest, err := spec.Digest(policy)
		if err != nil {
			return err
		}
		floor, err := store.PolicyFloor(ctx, target)
		if err != nil && !errors.Is(err, state.ErrPolicyFloorMissing) {
			return err
		}
		admitted := false
		if approved != "" {
			if approved != digest {
				return spec.Err(16, "approved policy digest differs from the selected independent policy")
			}
			if err = store.ObservePolicyFloor(ctx, target, policy.Spec.Epoch, digest); err != nil {
				return spec.Err(16, "out-of-band policy admission rejected: %v", err)
			}
			admitted = true
		}
		return o.emit(map[string]any{"targetID": target, "policyDigest": digest, "epoch": policy.Spec.Epoch, "previousFloor": floor, "admitted": admitted, "scope": "out-of-band customer policy admission; no cluster resources changed"})
	}}
	admit.Flags().StringVar(&site, "site", "", "Explicit Site with independently approved trust policy")
	admit.Flags().StringVar(&approved, "approved-digest", "", "Exact policy digest; absent means preview only")
	_ = admit.MarkFlagRequired("site")
	trust.AddCommand(admit)

	var signSite, candidatePath, key, keyID, decision, out string
	var validity time.Duration
	sign := &cobra.Command{Use: "update-sign", Short: "Sign a next-epoch policy packet using a current global policy administrator", RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, current, err := o.site(signSite)
		if err != nil {
			return err
		}
		candidate, err := loadPolicy(candidatePath)
		if err != nil {
			return err
		}
		eng, err := engine.New(s, nil)
		if err != nil {
			return err
		}
		target, err := eng.TargetIdentity(ctx)
		if err != nil {
			return err
		}
		previous, err := spec.Digest(current)
		if err != nil {
			return err
		}
		store, err := o.store()
		if err != nil {
			return err
		}
		defer store.Close()
		if err = store.CheckPolicyFloor(ctx, target, current.Spec.Epoch, previous); err != nil {
			return spec.Err(16, "current policy is not admitted for this target: %v", err)
		}
		if validity <= 0 || validity > trustupdate.MaxValidity {
			return spec.Err(2, "policy packet validity must be positive and at most 24 hours")
		}
		private, err := bundle.ReadPrivateKey(key)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		body := trustupdate.Body{Header: spec.NewHeader("TrustUpdate"), TargetID: target, PreviousPolicyDigest: previous, PreviousEpoch: current.Spec.Epoch, Candidate: candidate, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(validity).Format(time.RFC3339Nano), DecisionReference: decision}
		body.Metadata.Name = current.Metadata.Name
		packet, err := trustupdate.Sign(body, keyID, private)
		if err != nil {
			return err
		}
		preview, err := trustupdate.Verify(packet, current, target, now)
		if err != nil {
			return err
		}
		if err = trustupdate.Write(out, packet); err != nil {
			return err
		}
		return o.emit(map[string]any{"path": out, "packetDigest": preview.PacketDigest, "admitted": false})
	}}
	sign.Flags().StringVar(&signSite, "site", "", "Current independent Site/policy")
	sign.Flags().StringVar(&candidatePath, "candidate", "", "Reviewed exact next-epoch candidate")
	sign.Flags().StringVar(&key, "key", "", "Current policy administrator private key")
	sign.Flags().StringVar(&keyID, "key-id", "", "Current global policy administrator key ID")
	sign.Flags().StringVar(&decision, "decision-reference", "", "Customer decision or change reference")
	sign.Flags().StringVar(&out, "out", "trust-update.json", "New canonical packet file")
	sign.Flags().DurationVar(&validity, "valid-for", 30*time.Minute, "Positive validity no longer than 24 hours")
	for _, flag := range []string{"site", "candidate", "key", "key-id", "decision-reference"} {
		_ = sign.MarkFlagRequired(flag)
	}
	trust.AddCommand(sign)

	var previewSite string
	preview := &cobra.Command{Use: "update-preview PACKET", Args: cobra.ExactArgs(1), Short: "Verify a policy packet and display its exact policy changes without admission", RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, current, err := o.site(previewSite)
		if err != nil {
			return err
		}
		eng, err := engine.New(s, nil)
		if err != nil {
			return err
		}
		target, err := eng.TargetIdentity(ctx)
		if err != nil {
			return err
		}
		packet, err := trustupdate.Read(args[0])
		if err != nil {
			return err
		}
		store, err := o.store()
		if err != nil {
			return err
		}
		defer store.Close()
		digest, err := spec.Digest(current)
		if err != nil {
			return err
		}
		if err = store.CheckPolicyFloor(ctx, target, current.Spec.Epoch, digest); err != nil {
			return spec.Err(16, "current policy is not admitted for this target: %v", err)
		}
		result, err := trustupdate.Verify(packet, current, target, time.Now().UTC())
		if err != nil {
			return err
		}
		return o.emit(result)
	}}
	preview.Flags().StringVar(&previewSite, "site", "", "Current independent Site/policy")
	_ = preview.MarkFlagRequired("site")
	trust.AddCommand(preview)
	var updateSite, approvedPacket, policyOut string
	update := &cobra.Command{Use: "update-admit PACKET", Args: cobra.ExactArgs(1), Short: "Admit an exact reviewed packet and prepare a new policy file without overwriting the active file", RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, _, err := o.site(updateSite)
		if err != nil {
			return err
		}
		store, err := o.store()
		if err != nil {
			return err
		}
		defer store.Close()
		eng, err := engine.New(s, store)
		if err != nil {
			return err
		}
		target, err := eng.TargetIdentity(ctx)
		if err != nil {
			return err
		}
		packet, err := trustupdate.Read(args[0])
		if err != nil {
			return err
		}
		receipt, err := trustupdate.Admit(ctx, packet, s.Spec.TrustPolicy, target, approvedPacket, policyOut, store, time.Now().UTC())
		if receipt.Kind != "" {
			if outputErr := o.emit(receipt); outputErr != nil {
				return outputErr
			}
		}
		return err
	}}
	update.Flags().StringVar(&updateSite, "site", "", "Site referencing the current independent policy")
	update.Flags().StringVar(&approvedPacket, "approved-digest", "", "Exact reviewed packet digest")
	update.Flags().StringVar(&policyOut, "out", "", "New admitted policy path; update Site explicitly after success")
	for _, flag := range []string{"site", "approved-digest", "out"} {
		_ = update.MarkFlagRequired(flag)
	}
	trust.AddCommand(update)
}
