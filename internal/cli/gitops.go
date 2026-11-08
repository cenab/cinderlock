package cli

import (
	"os"

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
	var proposalSite, repository, head, target, manifest, manifestDigest, proposalOut string
	propose := &cobra.Command{Use: "propose BUNDLE", Short: "Write an inert source patch against an exact clean local Git commit", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, policy, err := o.site(proposalSite)
		if err != nil {
			return err
		}
		for _, path := range []string{s.Spec.StateDir, proposalOut, os.TempDir()} {
			if _, err = engine.GitOpsPreparationPath(repository, path); err != nil {
				return err
			}
		}
		v, err := bundle.Verify(ctx, args[0], policy)
		if err != nil {
			return err
		}
		defer v.Close()
		eng, err := engine.New(s, nil)
		if err != nil {
			return err
		}
		result, err := eng.ProposeGitOps(ctx, v, policy, absolute(proposalSite), repository, head, target, absolute(manifest), manifestDigest)
		if err != nil {
			return err
		}
		if err = engine.WriteGitOpsProposal(proposalOut, result); err != nil {
			return err
		}
		return o.emit(result)
	}}
	propose.Flags().StringVar(&proposalSite, "site", "", "Explicit private Site for the verified render")
	propose.Flags().StringVar(&repository, "repository", "", "Existing local Git repository; never fetched or modified")
	propose.Flags().StringVar(&head, "head", "", "Exact reviewed repository HEAD commit (40 or 64 lower-case hex)")
	propose.Flags().StringVar(&target, "path", "", "Tracked YAML file matching the signed GitOps path")
	propose.Flags().StringVar(&manifest, "manifest", "", "Existing reviewed desired-state manifest")
	propose.Flags().StringVar(&manifestDigest, "approved-manifest-digest", "", "Exact locally reviewed manifest SHA-256")
	propose.Flags().StringVar(&proposalOut, "out", "", "New private proposal file outside the repository")
	for _, flag := range []string{"site", "repository", "head", "path", "manifest", "approved-manifest-digest", "out"} {
		_ = propose.MarkFlagRequired(flag)
	}
	g.AddCommand(propose)
}
