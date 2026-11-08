package cli

import (
	"runtime"
	"runtime/debug"

	"github.com/cenab/cinderlock/internal/engine"
	"github.com/cenab/cinderlock/internal/sourceexport"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/spf13/cobra"
)

func addSource(root *cobra.Command, o *options) {
	g := &cobra.Command{Use: "source", Short: "Prepare and verify an admitted offline source distribution"}
	root.AddCommand(g)
	var out, goBinary, toolchain, helm, helmNotices string
	export := &cobra.Command{Use: "export PROJECT", Args: cobra.ExactArgs(1), Short: "Copy public sources, vendor dependencies and record exact toolchain identities", RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		manifest, err := sourceexport.Export(ctx, args[0], out, sourceexport.Options{GoBinary: goBinary, IncludeToolchain: toolchain, HelmPath: helm, HelmNotices: helmNotices})
		if err != nil {
			return err
		}
		digest, err := spec.Digest(manifest)
		if err != nil {
			return err
		}
		return o.emit(map[string]any{"path": out, "manifestDigest": digest, "trust": "content inventory; requires independent admission"})
	}}
	export.Flags().StringVar(&out, "out", "", "New private export directory")
	export.Flags().StringVar(&goBinary, "go", "", "Exact admitted Go binary; not a toolchain auto-selector")
	export.Flags().StringVar(&toolchain, "include-toolchain", "", "Optional admitted full GOROOT distribution")
	export.Flags().StringVar(&helm, "helm", "", "Optional admitted Helm executable")
	export.Flags().StringVar(&helmNotices, "helm-notices", "", "Required admitted license/notice directory when --helm is supplied")
	_ = export.MarkFlagRequired("out")
	_ = export.MarkFlagRequired("go")
	g.AddCommand(export)
	verify := &cobra.Command{Use: "verify DIRECTORY", Args: cobra.ExactArgs(1), Short: "Verify all exported files and reject changes or additions", RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		manifest, err := sourceexport.Verify(ctx, args[0])
		if err != nil {
			return err
		}
		digest, err := spec.Digest(manifest)
		if err != nil {
			return err
		}
		return o.emit(map[string]any{"verified": true, "manifestDigest": digest, "trust": "content inventory; requires independent admission"})
	}}
	g.AddCommand(verify)
	var buildGo, buildOut string
	build := &cobra.Command{Use: "build DIRECTORY", Args: cobra.ExactArgs(1), Short: "Verify and compile exported sources with network acquisition disabled", RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		if err := sourceexport.BuildOffline(ctx, args[0], buildGo, buildOut); err != nil {
			return err
		}
		return o.emit(map[string]any{"built": true, "source": args[0], "path": buildOut, "scope": "fixed CLI compilation with vendored dependencies; binary was not executed"})
	}}
	build.Flags().StringVar(&buildGo, "go", "", "Exact admitted Go binary matching export")
	build.Flags().StringVar(&buildOut, "out", "", "New executable path; no overwrite")
	_ = build.MarkFlagRequired("out")
	g.AddCommand(build)

	var site string
	doctor := &cobra.Command{Use: "doctor", Short: "Read local capabilities and optionally inspect an explicit target", RunE: func(c *cobra.Command, args []string) error {
		result := map[string]any{"version": Version, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "isolation": "not established by Cinderlock", "gpuQualification": "requires target-bound hardware evidence and application tests"}
		if info, ok := debug.ReadBuildInfo(); ok {
			result["mainModule"] = info.Main.Path
		}
		if site != "" {
			ctx, cancel := o.context(c)
			defer cancel()
			s, _, err := o.site(site)
			if err != nil {
				return err
			}
			eng, err := engine.New(s, nil)
			if err != nil {
				return err
			}
			snapshot, err := eng.Inspect(ctx)
			if err != nil {
				return err
			}
			result["snapshot"] = snapshot
		}
		return o.emit(result)
	}}
	doctor.Flags().StringVar(&site, "site", "", "Optional explicit private Site; never uses a default Kubernetes context")
	root.AddCommand(doctor)
}
