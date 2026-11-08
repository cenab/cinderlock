package cli

import (
	"context"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/catalog"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/spf13/cobra"
)

func (o *options) observation(ctx context.Context, id string) (catalog.Observation, error) {
	store, err := o.store()
	if err != nil {
		return catalog.Observation{}, err
	}
	defer store.Close()
	record, err := store.Run(ctx, id)
	if err != nil {
		return catalog.Observation{}, err
	}
	var result catalog.Observation
	for _, entry := range []struct {
		data   []byte
		target any
	}{{record.Plan, &result.Plan}, {record.Site, &result.Site}, {record.Result, &result.Run}} {
		if err := spec.Decode(entry.data, entry.target); err != nil {
			return result, err
		}
	}
	_, err = catalog.SubjectForObservation(result)
	return result, err
}

func addObservations(root *cobra.Command, o *options) {
	runs, _, _ := root.Find([]string{"run"})
	var maxAge time.Duration
	compare := &cobra.Command{Use: "compare BEFORE AFTER", Short: "Compare exact local recorded identities, coverage and outcomes", Args: cobra.ExactArgs(2), RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		before, err := o.observation(ctx, args[0])
		if err != nil {
			return err
		}
		after, err := o.observation(ctx, args[1])
		if err != nil {
			return err
		}
		result, err := catalog.CompareObservations(before, after, time.Now().UTC(), maxAge)
		if err != nil {
			return err
		}
		return o.emit(result)
	}}
	compare.Flags().DurationVar(&maxAge, "max-age", 24*time.Hour, "Recorded evidence freshness interval; never current health")
	runs.AddCommand(compare)

	evidence := &cobra.Command{Use: "evidence", Short: "Bind and verify producer-signed external evidence without changing run acceptance"}
	root.AddCommand(evidence)
	subject := &cobra.Command{Use: "subject RUN", Short: "Read the exact local subject identity for an external evidence producer", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		observation, err := o.observation(ctx, args[0])
		if err != nil {
			return err
		}
		result, err := catalog.SubjectForObservation(observation)
		if err != nil {
			return err
		}
		return o.emit(result)
	}}
	evidence.AddCommand(subject)
	var key, keyID, out string
	sign := &cobra.Command{Use: "sign BODY", Short: "Sign a complete typed producer evidence body in its separate signature domain", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		var body catalog.ExternalEvidence
		if err := read(args[0], &body); err != nil {
			return err
		}
		private, err := bundle.ReadPrivateKey(key)
		if err != nil {
			return err
		}
		packet, err := catalog.SignExternalEvidence(body, keyID, private)
		if err != nil {
			return err
		}
		if err = spec.Write(out, packet); err != nil {
			return err
		}
		digest, err := spec.Digest(packet)
		if err != nil {
			return err
		}
		return o.emit(map[string]string{"path": out, "digest": digest, "admission": "requires independently scoped evidence key"})
	}}
	sign.Flags().StringVar(&key, "key", "", "Producer private Ed25519 key")
	sign.Flags().StringVar(&keyID, "key-id", "", "Independently admitted producer key ID")
	sign.Flags().StringVar(&out, "out", "evidence.json", "New signed envelope path")
	_ = sign.MarkFlagRequired("key")
	_ = sign.MarkFlagRequired("key-id")
	evidence.AddCommand(sign)
	var keys, run, project, scope string
	verify := &cobra.Command{Use: "verify PACKET", Short: "Recheck signature, producer scope, expiry and exact local run binding", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		ctx, cancel := o.context(c)
		defer cancel()
		observation, err := o.observation(ctx, run)
		if err != nil {
			return err
		}
		subject, err := catalog.SubjectForObservation(observation)
		if err != nil {
			return err
		}
		var packet catalog.SignedExternalEvidence
		var admitted []catalog.EvidenceKey
		if err = read(args[0], &packet); err != nil {
			return err
		}
		if err = read(keys, &admitted); err != nil {
			return err
		}
		result, err := catalog.VerifyExternalEvidence(packet, admitted, catalog.EvidenceExpectation{Project: project, Site: observation.Run.SiteID, Subject: subject, Scope: scope}, time.Now().UTC())
		if err != nil {
			return spec.Err(12, "external evidence rejected: %v", err)
		}
		return o.emit(result)
	}}
	verify.Flags().StringVar(&keys, "keys", "", "Independent evidence key admission list")
	verify.Flags().StringVar(&run, "run", "", "Exact recorded local run")
	verify.Flags().StringVar(&project, "project", "", "Explicit evidence project")
	verify.Flags().StringVar(&scope, "scope", "", "Expected network-isolation, security-scan, model-evaluation or backup-restore scope")
	for _, flag := range []string{"keys", "run", "project", "scope"} {
		_ = verify.MarkFlagRequired(flag)
	}
	evidence.AddCommand(verify)
}
