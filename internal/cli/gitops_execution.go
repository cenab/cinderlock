package cli

import (
	"os"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/engine"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/spf13/cobra"
)

func (o *options) gitOpsPhasePaths(p spec.Plan, site spec.Site, outputs ...string) error {
	if p.GitOps == nil {
		return nil
	}
	repository := p.GitOps.Repository
	if p.GitOps.Contract != nil {
		repository = p.GitOps.Contract.Repository
	}
	for _, selected := range append([]string{o.state, o.cache, site.Spec.StateDir, os.TempDir()}, outputs...) {
		if _, err := engine.GitOpsPreparationPath(repository, selected); err != nil {
			return err
		}
	}
	return nil
}

func addGitOpsExecution(g *cobra.Command, o *options) {
	for _, prepare := range []bool{true, false} {
		var site, repository, contractPath, manifest, approvedDigest, staging, preparation, out string
		name, summary := "checks-plan", "Plan exact application checks against accepted source and fresh Argo evidence"
		if prepare {
			name, summary = "prepare-plan", "Plan fresh native revision volumes before customer source adoption"
		}
		command := &cobra.Command{Use: name + " BUNDLE", Short: summary, Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
			ctx, cancel := o.context(c)
			defer cancel()
			s, policy, err := o.site(site)
			if err != nil {
				return err
			}
			binding := spec.GitOpsPlanBinding{ManifestPath: absolute(manifest), Staging: spec.GitOpsRunReference{RunID: staging}, Repository: repository}
			if prepare {
				binding.Repository = absolute(repository)
			}
			if !prepare {
				binding.Contract = &spec.GitOpsProfileContract{}
				if err := spec.Read(contractPath, binding.Contract); err != nil {
					return err
				}
				if preparation != "" {
					binding.Preparation = &spec.GitOpsRunReference{RunID: preparation}
				}
			}
			if err := o.gitOpsPhasePaths(spec.Plan{GitOps: &binding}, s, out); err != nil {
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
			var plan spec.Plan
			if prepare {
				plan, err = eng.GitOpsPreparePlan(ctx, v, absolute(args[0]), absolute(site), policy, binding, approvedDigest)
			} else {
				plan, err = eng.GitOpsChecksPlan(ctx, v, absolute(args[0]), absolute(site), policy, binding)
			}
			if err != nil {
				return err
			}
			if err := engine.WriteGitOpsPhasePlan(plan, out); err != nil {
				return err
			}
			if err := o.emit(plan); err != nil {
				return err
			}
			if !plan.Executable {
				return spec.Err(10, "GitOps phase is blocked; inspect its findings")
			}
			return nil
		}}
		command.Flags().StringVar(&site, "site", "", "Explicit private Site and independently admitted policy")
		command.Flags().StringVar(&manifest, "manifest", "", "Exact reviewed desired-state file")
		command.Flags().StringVar(&staging, "staging-run", "", "Completed local artifacts_staged run for this exact bundle, Site and policy")
		command.Flags().StringVar(&out, "out", "", "New private phase plan outside the source repository")
		for _, flag := range []string{"site", "manifest", "staging-run", "out"} {
			_ = command.MarkFlagRequired(flag)
		}
		if prepare {
			command.Flags().StringVar(&repository, "repository", "", "Clean local source checkout at the exact signed proposal base")
			command.Flags().StringVar(&approvedDigest, "approved-manifest-digest", "", "Exact reviewed manifest SHA-256")
			_ = command.MarkFlagRequired("repository")
			_ = command.MarkFlagRequired("approved-manifest-digest")
		} else {
			command.Flags().StringVar(&contractPath, "contract", "", "Bounded accepted-source Argo contract")
			command.Flags().StringVar(&preparation, "preparation-run", "", "Completed native application-volume preparation when models are declared")
			_ = command.MarkFlagRequired("contract")
		}
		g.AddCommand(command)
	}
}

func (o *options) validateGitOpsApproval(c *cobra.Command, p spec.Plan, site spec.Site, policy spec.TrustPolicy, output string) error {
	if p.Kind != "GitOpsPreparePlan" && p.Kind != "GitOpsChecksPlan" {
		return nil
	}
	if err := o.gitOpsPhasePaths(p, site, output); err != nil {
		return err
	}
	ctx, cancel := o.context(c)
	defer cancel()
	v, err := bundle.Verify(ctx, p.BundlePath, policy)
	if err != nil {
		return err
	}
	defer v.Close()
	store, err := o.store()
	if err != nil {
		return err
	}
	defer store.Close()
	eng, err := engine.New(site, store)
	if err != nil {
		return err
	}
	return eng.ValidatePlan(ctx, p, v, policy)
}
