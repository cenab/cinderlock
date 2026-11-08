package cli

import (
	"context"
	"io"
	"os"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/engine"
	"github.com/cenab/cinderlock/internal/modelstage"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func readModelManifest(path string) ([]spec.FileRecord, string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() || info.Size() > modelstage.ManifestLimit {
		return nil, "", spec.Err(2, "model manifest must be a bounded regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, modelstage.ManifestLimit+1))
	if err != nil {
		return nil, "", err
	}
	if len(b) > modelstage.ManifestLimit {
		return nil, "", spec.Err(2, "model manifest exceeds 512 KiB")
	}
	var files []spec.FileRecord
	if err = spec.Decode(b, &files); err != nil {
		return nil, "", err
	}
	return files, spec.Hash(b), nil
}

func addLifecycleExtensions(root *cobra.Command, o *options) {
	helper := &cobra.Command{Use: "helper", Short: "Local bounded helpers used by declared verification Jobs"}
	root.AddCommand(helper)
	var directory, manifestPath, verifySubPath string
	verifyModel := &cobra.Command{Use: "verify-model", Short: "Verify an immutable model tree against its signed file manifest", RunE: func(c *cobra.Command, args []string) error {
		files, digest, err := readModelManifest(manifestPath)
		if err != nil {
			return err
		}
		if err = modelstage.VerifyAt(directory, verifySubPath, files); err != nil {
			return err
		}
		return o.emit(map[string]any{"verified": true, "manifestDigest": digest})
	}}
	verifyModel.Flags().StringVar(&directory, "root", "", "Read-only model directory")
	verifyModel.Flags().StringVar(&manifestPath, "manifest", "", "Trusted manifest outside the model volume")
	verifyModel.Flags().StringVar(&verifySubPath, "subpath", "", "Optional confined relative directory inside the model volume")
	_ = verifyModel.MarkFlagRequired("root")
	_ = verifyModel.MarkFlagRequired("manifest")
	helper.AddCommand(verifyModel)
	var receiveRoot, receiveSubPath, receiveManifest string
	receive := &cobra.Command{Use: "receive-model", Short: "Receive exact signed model files into a fresh confined volume directory", RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		files, digest, err := readModelManifest(receiveManifest)
		if err != nil {
			return err
		}
		if closer, ok := o.in.(io.Closer); ok {
			stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
			defer stop()
		}
		if err = modelstage.Receive(ctx, receiveRoot, receiveSubPath, files, o.in); err != nil {
			return err
		}
		return o.emit(map[string]any{"received": true, "manifestDigest": digest, "files": len(files)})
	}}
	receive.Flags().StringVar(&receiveRoot, "root", "", "Fresh model volume root")
	receive.Flags().StringVar(&receiveSubPath, "subpath", "", "Optional confined relative model directory")
	receive.Flags().StringVar(&receiveManifest, "manifest", "", "Immutable trusted file manifest")
	_ = receive.MarkFlagRequired("root")
	_ = receive.MarkFlagRequired("manifest")
	helper.AddCommand(receive)
	runs, _, _ := root.Find([]string{"run"})
	var site, out string
	retire := &cobra.Command{Use: "retirement-plan BUNDLE", Short: "Plan an uninstall that retains declared data objects and Helm history", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
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
		plan, err := eng.UninstallPlan(ctx, v, absolute(args[0]), absolute(site), policy)
		if err != nil {
			return err
		}
		if err = spec.Write(out, plan); err != nil {
			return err
		}
		return o.emit(plan)
	}}
	retire.Flags().StringVar(&site, "site", "", "Explicit Site path")
	retire.Flags().StringVar(&out, "out", "retirement-plan.json", "New plan path; execute separately with run apply")
	_ = retire.MarkFlagRequired("site")
	runs.AddCommand(retire)

	events := &cobra.Command{Use: "events RUN", Short: "Read recorded durable events without contacting the cluster", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		store, err := o.store()
		if err != nil {
			return err
		}
		defer store.Close()
		if _, err := store.Run(ctx, args[0]); err != nil {
			return err
		}
		items, err := store.Events(ctx, args[0])
		if err != nil {
			return err
		}
		return o.emit(items)
	}}
	runs.AddCommand(events)

	gitops := &cobra.Command{Use: "gitops", Short: "Stage signed images, propose source changes, and observe the external controller"}
	root.AddCommand(gitops)
	addGitOpsDelivery(gitops, o)
	var exportSite, exportOut string
	export := &cobra.Command{Use: "export BUNDLE", Short: "Render a verified chart with internal digest-pinned image bindings", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, policy, err := o.site(exportSite)
		if err != nil {
			return err
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
		manifest, err := eng.RenderDesiredState(ctx, v)
		if err != nil {
			return err
		}
		if err = spec.WriteBytes(exportOut, manifest); err != nil {
			return err
		}
		return o.emit(map[string]any{"path": exportOut, "digest": spec.Hash(manifest), "bundleDigest": v.Digest, "applicationAcceptance": "not_tested", "next": "Import bundled images and submit this state through the customer-controlled GitOps repository."})
	}}
	export.Flags().StringVar(&exportSite, "site", "", "Site with internal registry and pinned Helm executable")
	export.Flags().StringVar(&exportOut, "out", "desired-state.yaml", "New private manifest path")
	_ = export.MarkFlagRequired("site")
	gitops.AddCommand(export)
	var observeSite, owner, namespace, name, revision string
	observe := &cobra.Command{Use: "observe", Short: "Read exact-revision Argo CD or Flux controller status", RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, policy, err := o.site(observeSite)
		if err != nil {
			return err
		}
		eng, err := engine.New(s, nil)
		if err != nil {
			return err
		}
		result, err := eng.ObserveGitOps(ctx, owner, namespace, name, revision, policy)
		if err != nil {
			return err
		}
		if err = o.emit(result); err != nil {
			return err
		}
		if !result.ControllerReady {
			return spec.Err(10, "controller has not reported the requested revision ready")
		}
		return nil
	}}
	observe.Flags().StringVar(&observeSite, "site", "", "Explicit Site")
	observe.Flags().StringVar(&owner, "owner", "", "argocd or flux")
	observe.Flags().StringVar(&namespace, "namespace", "", "Controller object namespace")
	observe.Flags().StringVar(&name, "name", "", "Controller object name")
	observe.Flags().StringVar(&revision, "revision", "", "Exact expected revision")
	for _, flag := range []string{"site", "owner", "namespace", "name", "revision"} {
		_ = observe.MarkFlagRequired(flag)
	}
	gitops.AddCommand(observe)
}
