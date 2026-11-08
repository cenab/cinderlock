package cli

import (
	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/engine"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/spf13/cobra"
)

func addGitOpsDelivery(g *cobra.Command, o *options) {
	var site, out string
	plan := &cobra.Command{Use: "artifacts-plan BUNDLE", Short: "Plan authorized image-only staging for an external GitOps owner", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, policy, err := o.site(site)
		if err != nil {
			return err
		}
		v, err := bundle.Verify(ctx, args[0], policy)
		if err != nil {
			return err
		}
		defer v.Close()
		store, err := o.store()
		if err != nil {
			return err
		}
		defer store.Close()
		eng, err := engine.New(s, store)
		if err != nil {
			return err
		}
		result, err := eng.ArtifactsPlan(ctx, v, absolute(args[0]), absolute(site), policy)
		if err != nil {
			return err
		}
		if err = spec.Write(out, result); err != nil {
			return err
		}
		if err = o.emit(result); err != nil {
			return err
		}
		if !result.Executable {
			return spec.Err(10, "image staging plan is blocked; inspect its findings")
		}
		return nil
	}}
	plan.Flags().StringVar(&site, "site", "", "Explicit private Site with gitops-stage and import capabilities")
	plan.Flags().StringVar(&out, "out", "artifacts-plan.json", "New exact image staging plan")
	_ = plan.MarkFlagRequired("site")
	g.AddCommand(plan)
}
