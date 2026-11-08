package cli

import (
	"encoding/base64"
	"os"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/engine"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/transfer"
	"github.com/spf13/cobra"
)

func addAdvanced(root *cobra.Command, o *options) {
	release, _, _ := root.Find([]string{"release"})
	var inventoryOut string
	inventory := &cobra.Command{Use: "inventory LOCK", Short: "Generate incomplete-composition CycloneDX artifact inventory; no vulnerability scan claim", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		var l spec.ReleaseLock
		if e := read(a[0], &l); e != nil {
			return e
		}
		if e := spec.ValidateHeader(l.Header, "ReleaseLock"); e != nil {
			return e
		}
		bom, e := bundle.Inventory(l)
		if e != nil {
			return e
		}
		if inventoryOut != "" {
			if e = spec.Write(inventoryOut, bom); e != nil {
				return e
			}
		}
		return o.emit(bom)
	}}
	inventory.Flags().StringVar(&inventoryOut, "out", "", "Optional new inventory path")
	release.AddCommand(inventory)
	bundles, _, _ := root.Find([]string{"bundle"})
	var trust, sbomOut string
	sbom := &cobra.Command{Use: "sbom BUNDLE", Short: "Extract the artifact inventory bound by the signed index", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		p, e := loadPolicy(trust)
		if e != nil {
			return e
		}
		v, e := bundle.Verify(ctx, a[0], p)
		if e != nil {
			return e
		}
		defer v.Close()
		b, e := bundle.InventoryBytes(v)
		if e != nil {
			return e
		}
		if sbomOut != "" {
			if e = spec.WriteBytes(sbomOut, b); e != nil {
				return e
			}
			return o.emit(map[string]string{"path": sbomOut, "bundleDigest": v.Digest})
		}
		o.emitted = true
		_, e = o.out.Write(append(b, '\n'))
		return e
	}}
	sbom.Flags().StringVar(&trust, "trust", "", "Independent trust policy")
	sbom.Flags().StringVar(&sbomOut, "out", "", "New SBOM path; default stdout")
	_ = sbom.MarkFlagRequired("trust")
	bundles.AddCommand(sbom)
	var diffTrust, diffOut string
	diff := &cobra.Command{Use: "diff BASE TARGET", Short: "Create verified-object differential; receiver must retain the named base", Args: cobra.ExactArgs(2), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		p, e := loadPolicy(diffTrust)
		if e != nil {
			return e
		}
		base, e := bundle.Verify(ctx, a[0], p)
		if e != nil {
			return e
		}
		defer base.Close()
		target, e := bundle.Verify(ctx, a[1], p)
		if e != nil {
			return e
		}
		defer target.Close()
		r, e := transfer.CreateDelta(ctx, base, target, diffOut)
		if e != nil {
			return e
		}
		return o.emit(r)
	}}
	diff.Flags().StringVar(&diffTrust, "trust", "", "Policy authorizing both archive identities for this operation")
	diff.Flags().StringVar(&diffOut, "out", "delta", "New differential directory")
	_ = diff.MarkFlagRequired("trust")
	bundles.AddCommand(diff)
	var basePath, reconstructTrust, reconstructed string
	reconstruct := &cobra.Command{Use: "reconstruct DELTA", Short: "Rebuild and fully verify the signed target using an exact verified base", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		p, e := loadPolicy(reconstructTrust)
		if e != nil {
			return e
		}
		base, e := bundle.Verify(ctx, basePath, p)
		if e != nil {
			return e
		}
		defer base.Close()
		r, e := transfer.ReconstructDelta(ctx, a[0], base, p, reconstructed)
		if e != nil {
			return e
		}
		return o.emit(r)
	}}
	reconstruct.Flags().StringVar(&basePath, "base", "", "Retained base bundle")
	reconstruct.Flags().StringVar(&reconstructTrust, "trust", "", "Independent trust policy")
	reconstruct.Flags().StringVar(&reconstructed, "out", "reconstructed.cinder", "New verified full archive")
	_ = reconstruct.MarkFlagRequired("base")
	_ = reconstruct.MarkFlagRequired("trust")
	bundles.AddCommand(reconstruct)
	cache := &cobra.Command{Use: "cache", Short: "Reference-aware conservative local content cleanup"}
	root.AddCommand(cache)
	var gcOut string
	plan := &cobra.Command{Use: "plan", Short: "List unreferenced local blobs without deleting them", RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		p, e := bundle.PlanGC(ctx, o.cache)
		if e != nil {
			return e
		}
		if gcOut != "" {
			if e = spec.Write(gcOut, p); e != nil {
				return e
			}
		}
		return o.emit(p)
	}}
	plan.Flags().StringVar(&gcOut, "out", "", "Optional new GC plan")
	cache.AddCommand(plan)
	var approved string
	apply := &cobra.Command{Use: "apply PLAN", Short: "Delete only exact reviewed unused content after rechecking current references", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		var p bundle.GCPlan
		if e := read(a[0], &p); e != nil {
			return e
		}
		d, e := spec.Digest(p)
		if e != nil {
			return e
		}
		if d != approved || absolute(p.Cache) != absolute(o.cache) {
			return spec.Err(16, "GC plan digest or cache identity does not match approval")
		}
		if e = bundle.ApplyGC(ctx, p); e != nil {
			return e
		}
		return o.emit(map[string]any{"deletedObjects": len(p.Candidates), "bytes": p.Bytes})
	}}
	apply.Flags().StringVar(&approved, "approved-digest", "", "Exact GC plan digest")
	_ = apply.MarkFlagRequired("approved-digest")
	cache.AddCommand(apply)
	addPolicyUpdate(root, o)
	addHardware(root, o)
}

func addPolicyUpdate(root *cobra.Command, o *options) {
	g, _, _ := root.Find([]string{"trust"})
	var public, id, role, app, channel, revoke, out string
	c := &cobra.Command{Use: "propose-update POLICY", Short: "Create a higher-epoch candidate; admission remains the customer's independent process", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		p, e := loadPolicy(a[0])
		if e != nil {
			return e
		}
		if public == "" && revoke == "" {
			return spec.Err(2, "supply a new public key or revoked key ID")
		}
		if revoke != "" {
			found := false
			for i := range p.Spec.Keys {
				if p.Spec.Keys[i].ID == revoke {
					p.Spec.Keys[i].Revoked = true
					found = true
				}
			}
			if !found {
				return spec.Err(2, "revoked key ID is unknown")
			}
		}
		if public != "" {
			if role != "release" && role != "approval" && role != "policy" {
				return spec.Err(2, "role must be release, approval or policy")
			}
			if id == "" || app == "" {
				return spec.Err(2, "new key needs key-id and application scope")
			}
			for _, k := range p.Spec.Keys {
				if k.ID == id {
					return spec.Err(2, "key ID already exists; rotation needs a new ID")
				}
			}
			b, e := os.ReadFile(public)
			if e != nil {
				return e
			}
			key, e := bundle.ParsePublicKey(string(b))
			if e != nil {
				return e
			}
			p.Spec.Keys = append(p.Spec.Keys, spec.TrustedKey{ID: id, PublicKey: base64.StdEncoding.EncodeToString(key), Roles: []string{role}, Applications: []string{app}, Channels: []string{channel}})
		}
		p.Spec.Epoch++
		if e = spec.ValidatePolicy(p); e != nil {
			return e
		}
		if e = spec.Write(out, p); e != nil {
			return e
		}
		return o.emit(map[string]any{"path": out, "epoch": p.Spec.Epoch, "admitted": false, "next": "Review and admit through the customer's independent policy process; existing policy was not overwritten."})
	}}
	c.Flags().StringVar(&public, "public", "", "New public key path")
	c.Flags().StringVar(&id, "key-id", "", "New unique key ID")
	c.Flags().StringVar(&role, "role", "release", "release, approval or global customer policy administration")
	c.Flags().StringVar(&app, "application", "", "New key application scope")
	c.Flags().StringVar(&channel, "channel", "stable", "New key channel scope")
	c.Flags().StringVar(&revoke, "revoke", "", "Existing key ID to revoke")
	c.Flags().StringVar(&out, "out", "trust-update.json", "New candidate policy")
	g.AddCommand(c)
}

func addHardware(root *cobra.Command, o *options) {
	g, _, _ := root.Find([]string{"target"})
	var site, out, image, node string
	c := &cobra.Command{Use: "probe-plan BUNDLE", Short: "Plan an explicit GPU Job; this command itself is read-only", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, p, e := o.site(site)
		if e != nil {
			return e
		}
		v, e := bundle.Verify(ctx, a[0], p)
		if e != nil {
			return e
		}
		defer v.Close()
		store, e := o.store()
		if e != nil {
			return e
		}
		defer store.Close()
		eng, e := engine.New(s, store)
		if e != nil {
			return e
		}
		plan, e := eng.ProbePlan(ctx, v, absolute(a[0]), absolute(site), p, image, node)
		if e != nil {
			return e
		}
		if e = spec.Write(out, plan); e != nil {
			return e
		}
		return o.emit(plan)
	}}
	c.Flags().StringVar(&site, "site", "", "Explicit site")
	c.Flags().StringVar(&out, "out", "probe-plan.json", "New probe plan")
	c.Flags().StringVar(&image, "image", "", "Locked probe image asset ID")
	c.Flags().StringVar(&node, "node", "", "Explicit node to request GPU resources on")
	_ = c.MarkFlagRequired("site")
	_ = c.MarkFlagRequired("node")
	g.AddCommand(c)
	var evidenceOut string
	readEvidence := &cobra.Command{Use: "hardware-evidence RUN", Short: "Revalidate recorded GPU observations against original cluster evidence", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		store, e := o.store()
		if e != nil {
			return e
		}
		defer store.Close()
		record, e := store.Run(ctx, a[0])
		if e != nil {
			return e
		}
		var plan spec.Plan
		if e = spec.Decode(record.Plan, &plan); e != nil {
			return e
		}
		s, _, e := o.site(plan.SitePath)
		if e != nil {
			return e
		}
		eng, e := engine.New(s, store)
		if e != nil {
			return e
		}
		evidence, e := eng.HardwareEvidence(ctx, a[0])
		if e != nil {
			return e
		}
		if evidenceOut != "" {
			if e = spec.Write(evidenceOut, evidence); e != nil {
				return e
			}
		}
		return o.emit(evidence)
	}}
	readEvidence.Flags().StringVar(&evidenceOut, "out", "", "Optional private hardware evidence file")
	g.AddCommand(readEvidence)
}
