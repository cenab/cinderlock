package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cenab/cinderlock/internal/catalog"
	"github.com/cenab/cinderlock/internal/report"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/support"
	"github.com/spf13/cobra"
)

func (o *options) result(ctx context.Context, id string) (spec.RunResult, error) {
	s, e := o.store()
	if e != nil {
		return spec.RunResult{}, e
	}
	defer s.Close()
	r, e := s.Run(ctx, id)
	if e != nil {
		return spec.RunResult{}, e
	}
	var result spec.RunResult
	if e = spec.Decode(r.Result, &result); e != nil {
		return result, e
	}
	return result, spec.ValidateHeader(result.Header, "RunResult")
}
func addReports(run *cobra.Command, o *options) {
	var format, out string
	c := &cobra.Command{Use: "report RUN", Short: "Render local evidence without remote assets or uploads", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		if out == "" && format != "json" && o.output != "text" {
			return spec.Err(2, "machine output requires --out for non-JSON reports")
		}
		ctx, cancel := o.context(c)
		defer cancel()
		r, e := o.result(ctx, a[0])
		if e != nil {
			return e
		}
		if out == "" && format == "json" {
			return o.emit(r)
		}
		var b bytes.Buffer
		switch format {
		case "html":
			e = report.Render(&b, r)
		case "json":
			e = report.JSON(&b, r)
		case "markdown":
			e = report.Markdown(&b, r)
		default:
			return spec.Err(2, "format must be html, json or markdown")
		}
		if e != nil {
			return e
		}
		if out == "" {
			_, e = o.out.Write(b.Bytes())
			o.emitted = true
			return e
		}
		if e = spec.WriteBytes(out, b.Bytes()); e != nil {
			return e
		}
		return o.emit(map[string]string{"path": out, "format": format, "runID": a[0]})
	}}
	c.Flags().StringVar(&format, "format", "html", "html, json or markdown")
	c.Flags().StringVar(&out, "out", "", "New report path; default stdout")
	run.AddCommand(c)
}
func addSupport(root *cobra.Command, o *options) {
	g := &cobra.Command{Use: "support", Short: "Prepare local allowlisted diagnostics and explicitly reviewed exports"}
	root.AddCommand(g)
	for _, name := range []string{"collect", "export-preview"} {
		var out string
		c := &cobra.Command{Use: name + " RUN", Short: "Freeze a minimal structured summary, excluding raw diagnostics", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
			ctx, cancel := o.context(c)
			defer cancel()
			r, e := o.result(ctx, a[0])
			if e != nil {
				return e
			}
			p, e := support.Collect(r)
			if e != nil {
				return e
			}
			if out != "" {
				if e = spec.Write(out, p); e != nil {
					return e
				}
			}
			return o.emit(p)
		}}
		c.Flags().StringVar(&out, "out", "", "Optional new preview path")
		g.AddCommand(c)
	}
	var digest, out, site string
	c := &cobra.Command{Use: "export PREVIEW", Short: "Write exactly the policy-permitted reviewed snapshot locally; never upload", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, policy, e := o.site(site)
		if e != nil {
			return e
		}
		if !has(s.Spec.AllowedActions, "support-export") || !has(policy.Spec.AllowedActions, "support-export") {
			return spec.Err(16, "site and policy must both permit support-export")
		}
		var p support.Preview
		if e = read(a[0], &p); e != nil {
			return e
		}
		r, e := o.result(ctx, p.Summary.RunID)
		if e != nil {
			return e
		}
		if r.SiteID != s.Metadata.Name {
			return spec.Err(16, "support snapshot belongs to another site")
		}
		store, e := o.store()
		if e != nil {
			return e
		}
		record, e := store.Run(ctx, r.RunID)
		_ = store.Close()
		if e != nil {
			return e
		}
		var admitted spec.Site
		if e = spec.Decode(record.Site, &admitted); e != nil {
			return e
		}
		type binding struct{ Kubeconfig, Context, Namespace, ReleaseName, NamespaceUID, ClusterID string }
		bind := func(site spec.Site) binding {
			return binding{site.Spec.Kubeconfig, site.Spec.Context, site.Spec.Namespace, site.Spec.ReleaseName, site.Spec.NamespaceUID, site.Spec.ClusterID}
		}
		if bind(admitted) != bind(s) {
			return spec.Err(16, "support snapshot target binding differs from the selected site")
		}
		expected, e := support.Collect(r)
		if e != nil {
			return e
		}
		if expected.Digest != p.Digest {
			return spec.Err(11, "preview does not match recorded local result")
		}
		if e = support.Export(p, digest, out); e != nil {
			return e
		}
		return o.emit(map[string]string{"path": out, "approvedDigest": digest, "destination": "local file only"})
	}}
	c.Flags().StringVar(&digest, "approved-digest", "", "Exact reviewed snapshot digest")
	c.Flags().StringVar(&out, "out", "support-export.json", "New export path")
	c.Flags().StringVar(&site, "site", "", "Site policy controlling export")
	_ = c.MarkFlagRequired("approved-digest")
	_ = c.MarkFlagRequired("site")
	g.AddCommand(c)
}

func addCatalog(root *cobra.Command, o *options) {
	g := &cobra.Command{Use: "catalog", Short: "Optional self-hosted catalog; never a second deployment engine"}
	root.AddCommand(g)
	var tokenOut string
	token := &cobra.Command{Use: "token", Short: "Create a private local bearer-token file and show only its hash", RunE: func(c *cobra.Command, a []string) error {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			return e
		}
		token := hex.EncodeToString(b)
		if e := spec.WriteBytes(tokenOut, []byte(token+"\n")); e != nil {
			return e
		}
		return o.emit(map[string]string{"tokenFile": tokenOut, "tokenHash": catalog.TokenHash(token)})
	}}
	token.Flags().StringVar(&tokenOut, "out", "catalog.token", "New private token path")
	g.AddCommand(token)
	var config, address, cert, key, driver, database, dsnFile string
	var remote bool
	serve := &cobra.Command{Use: "serve", Short: "Serve an authenticated local dashboard and catalog API", RunE: func(c *cobra.Command, a []string) error {
		if e := catalog.ListenAddress(address, remote); e != nil {
			return e
		}
		if remote && (cert == "" || key == "") {
			return spec.Err(16, "remote binding requires TLS certificate and key")
		}
		ctx, cancel := context.WithTimeout(c.Context(), 30*time.Second)
		defer cancel()
		cfg, e := catalog.LoadConfig(ctx, config, nil)
		if e != nil {
			return e
		}
		dsn := database
		if driver != "sqlite" && driver != "pgx" {
			return spec.Err(2, "driver must be sqlite or pgx")
		}
		if driver == "pgx" {
			if dsnFile == "" {
				return spec.Err(2, "PostgreSQL requires --dsn-file; credentials are not accepted in flags")
			}
			info, e := os.Lstat(dsnFile)
			if e != nil {
				return e
			}
			if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return spec.Err(16, "DSN file must be a private regular file")
			}
			b, e := os.ReadFile(dsnFile)
			if e != nil {
				return e
			}
			if len(b) > 16384 {
				return spec.Err(2, "DSN file too large")
			}
			dsn = string(bytes.TrimSpace(b))
		}
		store, e := catalog.Open(ctx, driver, dsn)
		if e != nil {
			return e
		}
		defer store.Close()
		cfg.Store = store
		handler, e := catalog.NewHandler(cfg)
		if e != nil {
			return e
		}
		server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
		done := make(chan error, 1)
		go func() {
			if cert != "" && key != "" {
				done <- server.ListenAndServeTLS(cert, key)
			} else {
				done <- server.ListenAndServe()
			}
		}()
		if !o.quiet {
			fmt.Fprintln(o.err, "Cinderlock catalog listening on", address, "(authentication required)")
		}
		select {
		case err := <-done:
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		case <-c.Context().Done():
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return server.Shutdown(ctx)
		}
	}}
	serve.Flags().StringVar(&config, "config", "", "Private catalog configuration path")
	serve.Flags().StringVar(&driver, "driver", "sqlite", "sqlite or pgx")
	serve.Flags().StringVar(&database, "database", ".cinderlock/catalog.db", "SQLite database path")
	serve.Flags().StringVar(&dsnFile, "dsn-file", "", "Private PostgreSQL DSN file; never passed as a command argument")
	serve.Flags().StringVar(&address, "listen", "127.0.0.1:8088", "Loopback listener by default")
	serve.Flags().BoolVar(&remote, "allow-remote", false, "Explicitly allow non-loopback binding with TLS")
	serve.Flags().StringVar(&cert, "tls-cert", "", "TLS certificate path")
	serve.Flags().StringVar(&key, "tls-key", "", "TLS private key path")
	_ = serve.MarkFlagRequired("config")
	g.AddCommand(serve)
	g.AddCommand(&cobra.Command{Use: "hash-token FILE", Short: "Show a token hash without printing the token", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		b, e := os.ReadFile(a[0])
		if e != nil {
			return e
		}
		if len(b) < 32 || len(b) > 4096 {
			return spec.Err(2, "token must have at least 32 bytes and fit configured limits")
		}
		return o.emit(map[string]string{"tokenHash": catalog.TokenHash(string(bytes.TrimSpace(b)))})
	}})
}
