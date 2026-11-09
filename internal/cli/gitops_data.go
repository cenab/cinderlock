package cli

import (
	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/engine"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/spf13/cobra"
)

func addGitOpsData(g *cobra.Command, o *options) {
	for _, kind := range []string{"data-plan", "data-checks-plan", "data-recovery-plan"} {
		var site, manifest, contractPath, approved, staging, preparation, previous, previousManifest, predecessor, dataUID, sourceRun, recovery, out string
		var initial bool
		command := &cobra.Command{Use: kind + " BUNDLE", Short: "Plan signed mutable-data procedures without writing application desired state", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
			if kind == "data-checks-plan" && initial && (staging == "" || dataUID == "") {
				return spec.Err(2, "initial data adoption requires --staging-run and an independently selected --data-uid")
			}
			ctx, cancel := o.context(c)
			defer cancel()
			s, policy, err := o.site(site)
			if err != nil {
				return err
			}
			contract := &spec.GitOpsProfileContract{}
			if err := spec.Read(contractPath, contract); err != nil {
				return err
			}
			v, err := bundle.Verify(ctx, args[0], policy)
			if err != nil {
				return err
			}
			defer v.Close()
			declaration := v.Index.Lock.Release.Spec.Deployment.GitOps
			if declaration == nil || declaration.Data == nil {
				return spec.Err(10, "bundle has no signed GitOps data procedures")
			}
			store, err := o.store()
			if err != nil {
				return err
			}
			defer store.Close()
			data := &spec.GitOpsDataBinding{PVC: declaration.Data.PVC, UID: dataUID, Revision: s.Spec.DataRevision, BackupRef: s.Spec.BackupRef, Initial: initial}
			if previous != "" {
				data.Previous = &spec.GitOpsRunReference{RunID: previous}
				data.PreviousManifestPath = absolute(previousManifest)
			}
			if predecessor != "" {
				record, err := store.Run(ctx, predecessor)
				if err != nil {
					return err
				}
				var source spec.Plan
				if spec.Decode(record.Plan, &source) != nil || source.GitOps == nil || source.GitOps.Data == nil {
					return spec.Err(10, "predecessor has no data phase binding")
				}
				data.UID = source.GitOps.Data.UID
				data.Predecessor = &spec.GitOpsRunReference{RunID: predecessor}
			}
			binding := spec.GitOpsPlanBinding{ManifestPath: absolute(manifest), Contract: contract, Staging: spec.GitOpsRunReference{RunID: staging}, Data: data}
			if preparation != "" {
				binding.Preparation = &spec.GitOpsRunReference{RunID: preparation}
			}
			if err := o.gitOpsPhasePaths(spec.Plan{GitOps: &binding}, s, out); err != nil {
				return err
			}
			eng, err := engine.New(s, store)
			if err != nil {
				return err
			}
			var plan spec.Plan
			switch kind {
			case "data-plan":
				plan, err = eng.GitOpsDataPlan(ctx, v, absolute(args[0]), absolute(site), policy, binding, approved)
			case "data-checks-plan":
				plan, err = eng.GitOpsDataChecksPlan(ctx, v, absolute(args[0]), absolute(site), policy, binding)
			case "data-recovery-plan":
				plan, err = eng.GitOpsDataRecoveryPlan(ctx, sourceRun, recovery, v, absolute(args[0]), absolute(site), policy, binding)
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
				return spec.Err(10, "GitOps data plan is blocked; inspect its findings")
			}
			return nil
		}}
		command.Flags().StringVar(&site, "site", "", "Explicit private Site and independently admitted current policy")
		command.Flags().StringVar(&manifest, "manifest", "", "Exact reviewed target manifest outside the source checkout")
		command.Flags().StringVar(&contractPath, "contract", "", "Fresh current Argo source/controller contract")
		command.Flags().StringVar(&out, "out", "", "New private exact data phase plan")
		for _, flag := range []string{"site", "manifest", "contract", "out"} {
			_ = command.MarkFlagRequired(flag)
		}
		if kind == "data-recovery-plan" {
			command.Flags().StringVar(&sourceRun, "source-run", "", "Unresolved failed post-adoption run in this local journal")
			command.Flags().StringVar(&recovery, "recovery", "", "Exact signed same-source data recovery identity")
			_ = command.MarkFlagRequired("source-run")
			_ = command.MarkFlagRequired("recovery")
		} else {
			command.Flags().StringVar(&staging, "staging-run", "", "Completed image staging; inherited for a data successor")
			command.Flags().StringVar(&preparation, "preparation-run", "", "Completed native model preparation when models are declared")
			command.Flags().StringVar(&dataUID, "data-uid", "", "Independently selected original external mutable PVC UID")
			if kind == "data-plan" {
				command.Flags().StringVar(&previous, "previous-run", "", "Current accepted GitOps data application run")
				command.Flags().StringVar(&previousManifest, "previous-manifest", "", "Exact reviewed old manifest retained outside the source checkout")
				command.Flags().StringVar(&approved, "approved-manifest-digest", "", "Exact reviewed target manifest SHA-256")
				for _, flag := range []string{"staging-run", "data-uid", "previous-run", "previous-manifest", "approved-manifest-digest"} {
					_ = command.MarkFlagRequired(flag)
				}
			} else {
				command.Flags().StringVar(&predecessor, "predecessor-run", "", "Exact active awaiting-adoption run; its original PVC and artifact receipts are retained")
				command.Flags().BoolVar(&initial, "initial-data", false, "Explicit first installation into the independently selected external data PVC")
				command.MarkFlagsMutuallyExclusive("initial-data", "predecessor-run")
				command.MarkFlagsOneRequired("initial-data", "predecessor-run")
			}
		}
		g.AddCommand(command)
	}
}
