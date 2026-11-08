package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/discover"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/transfer"
	"github.com/spf13/cobra"
)

const Version = "0.1.0-dev"

type options struct {
	cache, state, output, color                      string
	command                                          string
	timeout                                          time.Duration
	noninteractive, quiet, verbose, emitted, started bool
	in                                               io.Reader
	out, err                                         io.Writer
}

func Execute(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) error {
	o := &options{in: in, out: out, err: stderr}
	root := newCommand(o)
	// Cobra can reject an unknown command before parsing persistent output flags.
	for i, arg := range args {
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "--output=") {
			o.output = strings.TrimPrefix(arg, "--output=")
		}
		if arg == "--output" && i+1 < len(args) {
			o.output = args[i+1]
		}
	}
	root.SetArgs(args)
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err != nil {
		if !o.started {
			err = spec.Err(2, "%v", err)
		}
		if ctx.Err() != nil && spec.ExitCode(err) == 19 {
			err = spec.Err(17, "local operation interrupted; inspect any durable run before retrying")
		}
		if o.output == "json" || o.output == "jsonl" {
			if !o.emitted {
				_ = o.emit(map[string]any{"apiVersion": spec.APIVersion, "kind": "Error", "code": spec.ExitCode(err), "message": err.Error()})
			}
		} else {
			fmt.Fprintln(stderr, err)
		}
	}
	return err
}
func newCommand(o *options) *cobra.Command {
	c := &cobra.Command{Use: "cinderlock", Short: "Prepare, deliver and operate offline application releases", Version: Version, SilenceUsage: true, SilenceErrors: true, PersistentPreRunE: func(c *cobra.Command, args []string) error {
		o.started = true
		o.command = c.CommandPath()
		if err := c.ValidateRequiredFlags(); err != nil {
			return spec.Err(2, "%v", err)
		}
		switch o.output {
		case "text", "json", "jsonl":
		default:
			return spec.Err(2, "output must be text, json or jsonl")
		}
		if o.timeout <= 0 {
			return spec.Err(2, "timeout must be positive")
		}
		switch o.color {
		case "auto", "always", "never":
		default:
			return spec.Err(2, "invalid color preference")
		}
		return nil
	}}
	c.PersistentFlags().StringVar(&o.cache, "cache", ".cinderlock/cache", "Private verified-content store")
	c.PersistentFlags().StringVar(&o.state, "state", ".cinderlock/state", "Private run state directory")
	c.PersistentFlags().StringVar(&o.output, "output", "text", "text, json or jsonl")
	c.PersistentFlags().DurationVar(&o.timeout, "timeout", 15*time.Minute, "Bounded local wait; not cancellation of committed remote work")
	c.PersistentFlags().BoolVar(&o.noninteractive, "no-interactive", false, "Never prompt; require any policy-mandated authorization")
	c.PersistentFlags().BoolVar(&o.quiet, "quiet", false, "Suppress routine progress")
	c.PersistentFlags().BoolVar(&o.verbose, "verbose", false, "Include safe diagnostic detail")
	c.PersistentFlags().StringVar(&o.color, "color", "auto", "auto, always or never")
	addRelease(c, o)
	addBundle(c, o)
	addTrust(c, o)
	addTarget(c, o)
	addRun(c, o)
	addSupport(c, o)
	addCatalog(c, o)
	addGroup(c, o)
	addAdvanced(c, o)
	addLifecycleExtensions(c, o)
	addSource(c, o)
	addObservations(c, o)
	addPolicyAdmission(c, o)
	addIntake(c, o)
	var proposalsOut string
	scan := &cobra.Command{Use: "scan DIRECTORY", Short: "Find potential acquisition and network dependencies without executing code", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		r, e := discover.Scan(ctx, a[0])
		if e != nil {
			return e
		}
		if proposalsOut != "" {
			proposals, err := discover.Propose(ctx, a[0])
			if err != nil {
				return err
			}
			if err = spec.Write(proposalsOut, proposals); err != nil {
				return err
			}
			r.ProposalPath = proposalsOut
			r.ProposalCount = len(proposals.Proposals)
		}
		return o.emit(r)
	}}
	scan.Flags().StringVar(&proposalsOut, "proposals-out", "", "Optional new private JSON file with reviewable configuration patches; never applies them")
	c.AddCommand(scan)
	c.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return spec.Err(2, "%v", err) })
	var exactArguments func(*cobra.Command)
	exactArguments = func(command *cobra.Command) {
		if command.RunE != nil && command.Args == nil {
			command.Args = cobra.NoArgs
		}
		for _, child := range command.Commands() {
			exactArguments(child)
		}
	}
	exactArguments(c)
	return c
}
func (o *options) context(c *cobra.Command) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.Context(), o.timeout)
}
func (o *options) emit(v any) error {
	o.emitted = true
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	if o.output == "jsonl" {
		v = map[string]any{"apiVersion": spec.APIVersion, "kind": "CommandEvent", "event": "result", "sequence": 1, "command": o.command, "result": v}
	} else if fields["apiVersion"] == nil || fields["kind"] == nil {
		v = map[string]any{"apiVersion": spec.APIVersion, "kind": "CommandResult", "command": o.command, "result": v}
	}
	enc := json.NewEncoder(o.out)
	enc.SetEscapeHTML(false)
	if o.output == "text" {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}
func read(path string, v any) error {
	if e := spec.Read(path, v); e != nil {
		return spec.Err(2, "read %s: %v", path, e)
	}
	return nil
}
func absolute(path string) string {
	p, e := filepath.Abs(path)
	if e != nil {
		return path
	}
	return p
}
func relative(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}
func loadPolicy(path string) (spec.TrustPolicy, error) {
	var p spec.TrustPolicy
	if e := read(path, &p); e != nil {
		return p, e
	}
	return p, spec.ValidatePolicy(p)
}
func loadSite(path string) (spec.Site, spec.TrustPolicy, error) {
	var s spec.Site
	if e := read(path, &s); e != nil {
		return s, spec.TrustPolicy{}, e
	}
	if e := spec.ValidateSite(s); e != nil {
		return s, spec.TrustPolicy{}, e
	}
	base := filepath.Dir(absolute(path))
	s = spec.ResolveSitePaths(s, base)
	p, e := loadPolicy(s.Spec.TrustPolicy)
	return s, p, e
}

func (o *options) site(path string) (spec.Site, spec.TrustPolicy, error) {
	s, p, err := loadSite(path)
	if s.Spec.StateDir == "" {
		s.Spec.StateDir = absolute(o.state)
	}
	return s, p, err
}

func addRelease(root *cobra.Command, o *options) {
	g := &cobra.Command{Use: "release", Short: "Declare and resolve release inputs"}
	root.AddCommand(g)
	var initOut string
	init := &cobra.Command{Use: "init", Short: "Write an intentionally incomplete release skeleton", RunE: func(c *cobra.Command, a []string) error {
		r := spec.Release{Header: spec.NewHeader("Release"), Spec: spec.ReleaseSpec{Profile: "kubernetes-cpu-lab", Deployment: spec.Deployment{Type: "helm", Chart: "./chart.tgz"}, Assets: []spec.Asset{}, RequiredChecks: []string{"application"}}}
		r.Metadata = spec.Metadata{Application: "my-application", Version: "1.0.0", Channel: "stable", Sequence: 1}
		if e := spec.Write(initOut, r); e != nil {
			return e
		}
		return o.emit(map[string]any{"path": initOut, "deployable": false, "next": "Declare artifacts, script safety contracts with explicit worker resources and timeouts, supported transitions, required checks and recovery before locking."})
	}}
	init.Flags().StringVar(&initOut, "out", "release.yaml", "New declaration path")
	g.AddCommand(init)
	for _, name := range []string{"show", "validate"} {
		name := name
		g.AddCommand(&cobra.Command{Use: name + " FILE", Short: name + " a strict release declaration", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
			var r spec.Release
			if e := read(a[0], &r); e != nil {
				return e
			}
			if e := spec.ValidateRelease(r); e != nil {
				return e
			}
			if name == "show" {
				return o.emit(r)
			}
			return o.emit(map[string]any{"valid": true, "application": r.Metadata.Application, "version": r.Metadata.Version})
		}})
	}
	var out, sourceAuth string
	lock := &cobra.Command{Use: "lock FILE", Short: "Acquire declared inputs and resolve immutable identities", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		var r spec.Release
		if e := read(a[0], &r); e != nil {
			return e
		}
		if e := spec.ValidateRelease(r); e != nil {
			return e
		}
		var opts bundle.LockOptions
		if sourceAuth != "" {
			workspace, e := filepath.EvalSymlinks(filepath.Dir(absolute(a[0])))
			if e != nil {
				return e
			}
			authPath, e := filepath.EvalSymlinks(absolute(sourceAuth))
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(workspace, authPath)
			if e != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				return spec.Err(2, "source credentials must remain outside the release workspace")
			}
			opts, e = bundle.ReadLockOptions(sourceAuth)
			if e != nil {
				return e
			}
		}
		l, e := bundle.LockWithOptions(ctx, a[0], o.cache, opts)
		if e != nil {
			return e
		}
		if e = spec.Write(out, l); e != nil {
			return e
		}
		d, e := spec.Digest(l)
		if e != nil {
			return e
		}
		return o.emit(map[string]any{"path": out, "digest": d, "assets": len(l.Assets)})
	}}
	lock.Flags().StringVar(&out, "out", "release.lock.json", "New lock path")
	lock.Flags().StringVar(&sourceAuth, "source-auth", "", "Private source credential scopes outside the release workspace")
	g.AddCommand(lock)
}
func addBundle(root *cobra.Command, o *options) {
	g := &cobra.Command{Use: "bundle", Short: "Build, verify and transfer signed offline releases"}
	root.AddCommand(g)
	var out, key, keyID string
	b := &cobra.Command{Use: "build LOCK", Short: "Build a signed archive from locked local content", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		var l spec.ReleaseLock
		if e := read(a[0], &l); e != nil {
			return e
		}
		if e := bundle.Build(ctx, l, o.cache, out, key, keyID); e != nil {
			return e
		}
		return o.emit(map[string]any{"path": out, "signedBy": keyID})
	}}
	b.Flags().StringVar(&out, "out", "release.cinder", "New archive path")
	b.Flags().StringVar(&key, "key", "", "Private signing key path")
	b.Flags().StringVar(&keyID, "key-id", "", "Independently enrolled signer ID")
	_ = b.MarkFlagRequired("key")
	_ = b.MarkFlagRequired("key-id")
	g.AddCommand(b)
	for _, name := range []string{"show", "verify"} {
		name := name
		var trust string
		c := &cobra.Command{Use: name + " BUNDLE", Short: "Authenticate and fully verify a release before inspection", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
			ctx, cancel := o.context(c)
			defer cancel()
			p, e := loadPolicy(trust)
			if e != nil {
				return e
			}
			v, e := bundle.Verify(ctx, a[0], p)
			if e != nil {
				return spec.Err(12, "bundle rejected: %v", e)
			}
			defer v.Close()
			if name == "show" {
				return o.emit(v.Index)
			}
			return o.emit(map[string]any{"verified": true, "digest": v.Digest, "payloads": len(v.Index.Payloads), "application": v.Index.Lock.Release.Metadata.Application})
		}}
		c.Flags().StringVar(&trust, "trust", "", "Independent trust policy path")
		_ = c.MarkFlagRequired("trust")
		g.AddCommand(c)
	}
	var parts string
	var size int64
	split := &cobra.Command{Use: "split BUNDLE", Short: "Split transport bytes; recipient must still verify the signed bundle", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		r, e := transfer.Split(ctx, a[0], parts, size)
		if e != nil {
			return e
		}
		return o.emit(r)
	}}
	split.Flags().StringVar(&parts, "out", "parts", "New parts directory")
	split.Flags().Int64Var(&size, "part-size", 128<<20, "Maximum bytes per part")
	g.AddCommand(split)
	var joined string
	join := &cobra.Command{Use: "join DIRECTORY", Short: "Reconstruct parts and verify transport digests; bundle trust is separate", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		r, e := transfer.Join(ctx, a[0], joined)
		if e != nil {
			return e
		}
		return o.emit(r)
	}}
	join.Flags().StringVar(&joined, "out", "received.cinder", "New bundle path")
	g.AddCommand(join)
}
func addTrust(root *cobra.Command, o *options) {
	g := &cobra.Command{Use: "trust", Short: "Manage local keys and independently admitted trust policy"}
	root.AddCommand(g)
	var private, public string
	k := &cobra.Command{Use: "keygen", Short: "Create private Ed25519 key files without overwriting existing keys", RunE: func(c *cobra.Command, a []string) error {
		if e := os.MkdirAll(filepath.Dir(private), 0700); e != nil {
			return e
		}
		if e := os.MkdirAll(filepath.Dir(public), 0700); e != nil {
			return e
		}
		if e := bundle.GenerateKey(private, public); e != nil {
			return e
		}
		return o.emit(map[string]string{"privateKey": private, "publicKey": public})
	}}
	k.Flags().StringVar(&private, "private", "signing.key", "New private key path")
	k.Flags().StringVar(&public, "public", "signing.pub", "New public key path")
	g.AddCommand(k)
	for _, name := range []string{"show", "validate"} {
		name := name
		g.AddCommand(&cobra.Command{Use: name + " POLICY", Short: "Read an independent local trust policy", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
			p, e := loadPolicy(a[0])
			if e != nil {
				return e
			}
			if name == "show" {
				return o.emit(p)
			}
			d, e := spec.Digest(p)
			if e != nil {
				return e
			}
			return o.emit(map[string]any{"valid": true, "digest": d, "epoch": p.Spec.Epoch})
		}})
	}
	var pub, id, app, channel, policyOut string
	init := &cobra.Command{Use: "init", Short: "Create a candidate policy for explicit local review and admission", RunE: func(c *cobra.Command, a []string) error {
		b, e := os.ReadFile(pub)
		if e != nil {
			return e
		}
		pk, e := bundle.ParsePublicKey(string(b))
		if e != nil {
			return e
		}
		p := spec.TrustPolicy{Header: spec.NewHeader("TrustPolicy"), Spec: spec.TrustSpec{Epoch: 1, Keys: []spec.TrustedKey{{ID: id, PublicKey: base64.StdEncoding.EncodeToString(ed25519.PublicKey(pk)), Applications: []string{app}, Channels: []string{channel}, Roles: []string{"release"}}}, AllowedActions: []string{"import", "helm", "job", "migrate", "backup", "reindex", "restart", "seed"}, RequireAuthorization: true}}
		p.Metadata.Name = "site-policy"
		if e = spec.ValidatePolicy(p); e != nil {
			return e
		}
		if e = spec.Write(policyOut, p); e != nil {
			return e
		}
		return o.emit(map[string]any{"path": policyOut, "admitted": false, "next": "Review out-of-band and add a separate customer approval key before execution."})
	}}
	init.Flags().StringVar(&pub, "public", "", "Public key path")
	init.Flags().StringVar(&id, "key-id", "release", "Signer ID")
	init.Flags().StringVar(&app, "application", "", "Permitted application")
	init.Flags().StringVar(&channel, "channel", "stable", "Permitted channel")
	init.Flags().StringVar(&policyOut, "out", "trust.json", "New candidate policy path")
	_ = init.MarkFlagRequired("public")
	_ = init.MarkFlagRequired("application")
	g.AddCommand(init)
}
