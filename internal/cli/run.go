package cli

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/engine"
	"github.com/cenab/cinderlock/internal/group"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/state"
	"github.com/spf13/cobra"
)

func (o *options) store() (*state.Store, error) { return state.Open(filepath.Join(o.state, "runs.db")) }
func blockers(fs []spec.Finding) bool {
	for _, f := range fs {
		if f.Severity == "error" || f.Severity == "blocker" || f.Severity == "blocked" {
			return true
		}
	}
	return false
}
func addTarget(root *cobra.Command, o *options) {
	g := &cobra.Command{Use: "target", Short: "Read-only inspection against an explicit target configuration"}
	root.AddCommand(g)
	var site, out string
	var check bool
	c := &cobra.Command{Use: "inspect", Short: "Observe actual namespace, release, resources and permitted GPU facts", RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, _, e := o.site(site)
		if e != nil {
			return e
		}
		store, e := o.store()
		if e != nil {
			return e
		}
		defer store.Close()
		eng, e := engine.New(s, store)
		if e != nil {
			return e
		}
		snapshot, e := eng.Inspect(ctx)
		if e != nil {
			return e
		}
		if out != "" {
			if e = spec.Write(out, snapshot); e != nil {
				return e
			}
		}
		if e = o.emit(snapshot); e != nil {
			return e
		}
		if check && blockers(snapshot.Findings) {
			return spec.Err(20, "target inspection found blocking conditions")
		}
		return nil
	}}
	c.Flags().StringVar(&site, "site", "", "Private Site path")
	c.Flags().StringVar(&out, "out", "", "Optional new snapshot path")
	c.Flags().BoolVar(&check, "check", false, "Return code 20 for blocking findings")
	_ = c.MarkFlagRequired("site")
	g.AddCommand(c)
	g.AddCommand(&cobra.Command{Use: "show SNAPSHOT", Short: "Read an existing local snapshot without contacting the target", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		var s spec.TargetSnapshot
		if e := read(a[0], &s); e != nil {
			return e
		}
		if e := spec.ValidateHeader(s.Header, "TargetSnapshot"); e != nil {
			return e
		}
		return o.emit(s)
	}})
}
func addRun(root *cobra.Command, o *options) {
	g := &cobra.Command{Use: "run", Short: "Plan, execute, reconcile and recover a supported transition"}
	root.AddCommand(g)
	var site, out string
	plan := &cobra.Command{Use: "plan BUNDLE", Short: "Read-only target-bound plan; writes no application resources", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, p, e := o.site(site)
		if e != nil {
			return e
		}
		v, e := bundle.Verify(ctx, a[0], p)
		if e != nil {
			return spec.Err(12, "bundle rejected: %v", e)
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
		r, e := eng.Plan(ctx, v, absolute(a[0]), absolute(site), p)
		if e != nil {
			return e
		}
		if e = spec.Write(out, r); e != nil {
			return e
		}
		if e = o.emit(r); e != nil {
			return e
		}
		if !r.Executable {
			return spec.Err(10, "plan is blocked; inspect findings before generating a new plan")
		}
		return nil
	}}
	plan.Flags().StringVar(&site, "site", "", "Site configuration")
	plan.Flags().StringVar(&out, "out", "plan.json", "New immutable plan path")
	_ = plan.MarkFlagRequired("site")
	g.AddCommand(plan)
	var auth string
	apply := &cobra.Command{Use: "apply PLAN", Short: "Execute the exact reviewed plan under current site policy", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		var p spec.Plan
		if e := read(a[0], &p); e != nil {
			return e
		}
		r, e := o.applyPlan(c, p, auth)
		if r.RunID != "" {
			if emitErr := o.emit(r); emitErr != nil {
				return emitErr
			}
		}
		return e
	}}
	apply.Flags().StringVar(&auth, "authorization", "", "Customer-signed exact-plan authorization")
	g.AddCommand(apply)
	var check bool
	status := &cobra.Command{Use: "status RUN", Short: "Read durable local state; --check returns the application outcome", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, e := o.store()
		if e != nil {
			return e
		}
		defer s.Close()
		r, e := s.Run(ctx, a[0])
		if e != nil {
			return e
		}
		if e = o.emit(r); e != nil {
			return e
		}
		if check {
			switch r.State {
			case "succeeded", "recovered":
				return nil
			case "needs_reconciliation":
				return spec.Err(13, "run requires reconciliation")
			case "failed", "recovery_failed":
				return spec.Err(15, "run did not meet required acceptance")
			case "artifacts_staged":
				return spec.Err(10, "images are staged; application acceptance is not established")
			case "artifacts_failed":
				return spec.Err(15, "image staging failed; application acceptance is not established")
			default:
				return spec.Err(10, "run is not complete")
			}
		}
		return nil
	}}
	status.Flags().BoolVar(&check, "check", false, "Return nonzero unless run succeeded or recovered")
	g.AddCommand(status)
	g.AddCommand(&cobra.Command{Use: "list", Short: "List recorded runs without contacting a cluster", RunE: func(c *cobra.Command, a []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		s, e := o.store()
		if e != nil {
			return e
		}
		defer s.Close()
		r, e := s.Runs(ctx)
		if e != nil {
			return e
		}
		return o.emit(r)
	}})
	var resumeAuth string
	resume := &cobra.Command{Use: "resume RUN", Short: "Reconcile current facts before continuing unfinished work", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
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
		var p spec.Plan
		if e = spec.Decode(record.Plan, &p); e != nil {
			return e
		}
		s, policy, e := o.site(p.SitePath)
		if e != nil {
			return e
		}
		v, e := bundle.Verify(ctx, p.BundlePath, policy)
		if e != nil {
			return spec.Err(12, "bundle rejected: %v", e)
		}
		defer v.Close()
		authorization, e := readAuthorization(resumeAuth)
		if e != nil {
			return e
		}
		approved, e := o.confirm(p, policy, authorization != nil)
		if e != nil {
			return e
		}
		eng, e := engine.New(s, store)
		if e != nil {
			return e
		}
		r, e := eng.Resume(ctx, a[0], v, policy, authorization, approved)
		if r.RunID != "" {
			if x := o.emit(r); x != nil {
				return x
			}
		}
		return e
	}}
	resume.Flags().StringVar(&resumeAuth, "authorization", "", "Still-valid plan-bound authorization")
	g.AddCommand(resume)
	var recoveryID, recoveryOut string
	recovery := &cobra.Command{Use: "recovery-plan RUN", Short: "Read actual state and produce a separately reviewable recovery plan", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
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
		var original spec.Plan
		if e = spec.Decode(record.Plan, &original); e != nil {
			return e
		}
		s, p, e := o.site(original.SitePath)
		if e != nil {
			return e
		}
		eng, e := engine.New(s, store)
		if e != nil {
			return e
		}
		r, e := eng.RecoveryPlan(ctx, a[0], recoveryID, original.BundlePath, original.SitePath, p)
		if e != nil {
			return e
		}
		if e = spec.Write(recoveryOut, r); e != nil {
			return e
		}
		return o.emit(r)
	}}
	recovery.Flags().StringVar(&recoveryID, "recovery", "", "Declared recovery procedure ID")
	recovery.Flags().StringVar(&recoveryOut, "out", "recovery-plan.json", "New recovery plan path")
	_ = recovery.MarkFlagRequired("recovery")
	g.AddCommand(recovery)
	var recoverPlan, recoverAuth string
	recover := &cobra.Command{Use: "recover RUN", Short: "Execute one separately authorized recovery from current state", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		var p spec.Plan
		if e := read(recoverPlan, &p); e != nil {
			return e
		}
		if p.Kind != "RecoveryPlan" || p.SourceRun != a[0] {
			return spec.Err(16, "recovery plan does not bind this run")
		}
		r, e := o.applyPlan(c, p, recoverAuth)
		if r.RunID != "" {
			if x := o.emit(r); x != nil {
				return x
			}
		}
		return e
	}}
	recover.Flags().StringVar(&recoverPlan, "plan", "", "Reviewed recovery plan")
	recover.Flags().StringVar(&recoverAuth, "authorization", "", "Separate recovery authorization")
	_ = recover.MarkFlagRequired("plan")
	g.AddCommand(recover)
	addAuthorize(g, o)
	addReports(g, o)
}
func readAuthorization(path string) (*spec.Authorization, error) {
	if path == "" {
		return nil, nil
	}
	var a spec.Authorization
	if e := read(path, &a); e != nil {
		return nil, e
	}
	return &a, nil
}
func (o *options) confirm(p spec.Plan, policy spec.TrustPolicy, hasAuthorization bool) (bool, error) {
	if hasAuthorization {
		return false, nil
	}
	if policy.Spec.RequireAuthorization || !policy.Spec.AllowInteractive {
		return false, spec.Err(16, "policy requires a customer authorization file")
	}
	if o.noninteractive {
		return false, spec.Err(16, "interactive approval unavailable; provide --authorization")
	}
	d, e := spec.Digest(p)
	if e != nil {
		return false, e
	}
	fmt.Fprintf(o.err, "Target: %s\nApplication: %s %s -> %s\nPlan: %s\nType this exact plan digest to approve: ", p.Snapshot.TargetID, p.Metadata.Application, p.SourceVersion, p.TargetVersion, d)
	line, e := bufio.NewReader(o.in).ReadString('\n')
	if e != nil {
		return false, spec.Err(16, "approval not completed")
	}
	if strings.TrimSpace(line) != d {
		return false, spec.Err(16, "approval does not match plan")
	}
	return true, nil
}
func (o *options) applyPlan(c *cobra.Command, p spec.Plan, authPath string) (spec.RunResult, error) {
	ctx, cancel := o.context(c)
	defer cancel()
	s, policy, e := o.site(p.SitePath)
	if e != nil {
		return spec.RunResult{}, e
	}
	v, e := bundle.Verify(ctx, p.BundlePath, policy)
	if e != nil {
		return spec.RunResult{}, spec.Err(12, "bundle rejected: %v", e)
	}
	defer v.Close()
	auth, e := readAuthorization(authPath)
	if e != nil {
		return spec.RunResult{}, e
	}
	approved, e := o.confirm(p, policy, auth != nil)
	if e != nil {
		return spec.RunResult{}, e
	}
	store, e := o.store()
	if e != nil {
		return spec.RunResult{}, e
	}
	defer store.Close()
	eng, e := engine.New(s, store)
	if e != nil {
		return spec.RunResult{}, e
	}
	return eng.Apply(ctx, p, v, policy, auth, approved)
}
func addAuthorize(g *cobra.Command, o *options) {
	var key, id, out string
	var validity time.Duration
	c := &cobra.Command{Use: "authorize PLAN", Short: "Sign a plan using an independently admitted customer approval key", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		var p spec.Plan
		if e := read(args[0], &p); e != nil {
			return e
		}
		if !p.Executable {
			return spec.Err(16, "cannot authorize a blocked plan")
		}
		site, policy, e := o.site(p.SitePath)
		if e != nil {
			return e
		}
		pd, e := spec.Digest(policy)
		if e != nil {
			return e
		}
		if pd != p.PolicyDigest || policy.Spec.Epoch != p.PolicyEpoch {
			return spec.Err(11, "plan policy is stale")
		}
		private, e := bundle.ReadPrivateKey(key)
		if e != nil {
			return e
		}
		permitted := false
		for _, k := range policy.Spec.Keys {
			if k.ID != id || k.Revoked {
				continue
			}
			pub, x := base64.StdEncoding.DecodeString(k.PublicKey)
			if x != nil {
				continue
			}
			same := ed25519.PublicKey(pub).Equal(private.Public())
			if same && has(k.Roles, "approval") && scope(k.Applications, p.Metadata.Application) && scope(k.Channels, p.Metadata.Channel) {
				permitted = true
			}
		}
		if !permitted {
			return spec.Err(16, "key is not admitted for customer approval of this application/channel")
		}
		if validity <= 0 || validity > 24*time.Hour {
			return spec.Err(2, "authorization validity must be within 24 hours")
		}
		d, e := spec.Digest(p)
		if e != nil {
			return e
		}
		nonce := make([]byte, 24)
		if _, e = rand.Read(nonce); e != nil {
			return e
		}
		actions := []string{}
		for _, op := range p.Operations {
			if !has(policy.Spec.AllowedActions, op.Type) {
				return spec.Err(16, "operation %s is outside policy", op.ID)
			}
			if !has(actions, op.Type) {
				actions = append(actions, op.Type)
			}
		}
		for _, capability := range spec.EndpointActions(p.Checks) {
			if !has(site.Spec.AllowedActions, capability) || !has(policy.Spec.AllowedActions, capability) {
				return spec.Err(16, "endpoint prerequisite capability %s is outside site or policy", capability)
			}
			if !has(actions, capability) {
				actions = append(actions, capability)
			}
		}
		a := spec.Authorization{Header: spec.NewHeader("Authorization"), PlanDigest: d, PlanKind: p.Kind, TargetID: p.Snapshot.TargetID, PolicyDigest: pd, PolicyEpoch: policy.Spec.Epoch, Actions: actions, ExpiresAt: time.Now().UTC().Add(validity).Format(time.RFC3339), Nonce: hex.EncodeToString(nonce)}
		a.Metadata = p.Metadata
		if e = spec.SignAuthorization(&a, private, id); e != nil {
			return e
		}
		if e = spec.Write(out, a); e != nil {
			return e
		}
		return o.emit(map[string]any{"path": out, "planDigest": d, "expiresAt": a.ExpiresAt})
	}}
	c.Flags().StringVar(&key, "key", "", "Customer approval private key")
	c.Flags().StringVar(&id, "key-id", "", "Admitted approval key ID")
	c.Flags().StringVar(&out, "out", "authorization.json", "New authorization path")
	c.Flags().DurationVar(&validity, "valid-for", 30*time.Minute, "Authorization lifetime")
	_ = c.MarkFlagRequired("key")
	_ = c.MarkFlagRequired("key-id")
	g.AddCommand(c)
}
func has(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func scope(a []string, s string) bool { return has(a, s) || has(a, "*") }
func addGroup(root *cobra.Command, o *options) {
	g := &cobra.Command{Use: "group", Short: "Ordered multi-application transitions with explicit partial outcomes"}
	root.AddCommand(g)
	g.AddCommand(&cobra.Command{Use: "apply GROUP", Short: "Execute dependency-ordered independently authorized plans; stop on first failure", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		var r group.Group
		if e := read(a[0], &r); e != nil {
			return e
		}
		base := filepath.Dir(absolute(a[0]))
		plans := map[string]spec.Plan{}
		for _, entry := range r.Entries {
			var p spec.Plan
			if err := read(relative(base, entry.Plan), &p); err != nil {
				return err
			}
			plans[entry.ID] = p
		}
		if err := group.ValidatePlans(r, plans); err != nil {
			return err
		}
		ctx, cancel := o.context(c)
		defer cancel()
		c.SetContext(ctx)
		result, e := group.Apply(ctx, r, func(_ context.Context, x group.Entry) (spec.RunResult, error) {
			return o.applyPlan(c, plans[x.ID], relative(base, x.Authorization))
		})
		if x := o.emit(result); x != nil {
			return x
		}
		return e
	}})
}
