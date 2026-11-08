package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/endpointprobe"
	"github.com/cenab/cinderlock/internal/spec"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func endpointRun(t *testing.T) (*Engine, *fake.Clientset, spec.TrustPolicy, spec.Plan, *bundle.Verified) {
	t.Helper()
	e, client, policy := fixture(t)
	e.Site.Spec.HelperImage = "sha256:" + strings.Repeat("d", 64)
	e.Site.Spec.AllowedHosts = []string{"registry.internal"}
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "endpoint-probe")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "endpoint-probe")
	policy.Spec.Epoch++
	admitFixturePolicy(t, e, policy)
	e.Site.Spec.SecretRefs = map[string]spec.SecretRef{"corp-ca": {Name: "endpoint-materials", Key: "ca"}, "header": {Name: "endpoint-materials", Key: "authorization"}}
	if _, err := client.CoreV1().Secrets("test").Create(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "endpoint-materials", Namespace: "test", UID: "endpoint-materials-uid", ResourceVersion: "1"}, Data: map[string][]byte{"ca": []byte("synthetic CA"), "authorization": []byte("Bearer synthetic")}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	p, v := fixturePlan(t, e, policy)
	v.Index.Lock.Assets = append(v.Index.Lock.Assets, spec.LockedAsset{ID: "helper", Type: "image", Digest: e.Site.Spec.HelperImage})
	v.Index.Lock.Release.Spec.Assets = append(v.Index.Lock.Release.Spec.Assets, spec.Asset{ID: "helper", Type: "image", Source: "registry.invalid/helper:1"})
	check := spec.Check{ID: "registry-route", Type: "endpoint", Domain: "readiness", Required: true, URL: "https://registry.internal/v2/", ExpectedStatus: 200, CASecretRef: "corp-ca", AuthorizationSecretRef: "header", SecretRefs: []string{"corp-ca", "header"}}
	v.Index.Lock.Release.Spec.Checks = append(v.Index.Lock.Release.Spec.Checks, check)
	v.Index.Lock.Release.Spec.Recovery[0].Checks = v.Index.Lock.Release.Spec.Checks
	p.Checks, p.Recovery = v.Index.Lock.Release.Spec.Checks, v.Index.Lock.Release.Spec.Recovery
	return e, client, policy, p, v
}

func bindEndpointSite(t *testing.T, e *Engine, p *spec.Plan, policy spec.TrustPolicy) {
	t.Helper()
	body, err := spec.Canonical(e.Site)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.SitePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	p.SiteDigest, p.PolicyDigest, p.PolicyEpoch = mustDigest(t, e.Site), mustDigest(t, policy), policy.Spec.Epoch
	p.SourceSiteDigest, err = sourceSiteDigest(p.SitePath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := e.Inspect(context.Background())
	if err != nil {
		if spec.ExitCode(err) == 16 {
			return
		}
		t.Fatal(err)
	}
	p.Snapshot = snapshot
	p.SnapshotDigest, err = snapshotDigest(p.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEndpointJobIsFixedPrerequisiteAndNeverBlindlyRepeated(t *testing.T) {
	for _, outcome := range []string{"pass", "failed", "lost-ack"} {
		t.Run(outcome, func(t *testing.T) {
			e, client, policy, p, v := endpointRun(t)
			storeResumePlan(t, e, p, v, "endpoint-run")
			created := []string{}
			client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
				job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
				container := job.Spec.Template.Spec.Containers[0]
				created = append(created, container.Command[0])
				job.UID = types.UID("uid-" + job.Name)
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
				if container.Command[0] != "/usr/local/bin/cinderlock" {
					return false, nil, nil
				}
				if !slices.Equal(container.Command, []string{"/usr/local/bin/cinderlock", "helper", "endpoint-probe"}) || container.Image != e.Site.Spec.Registry+"/helper@"+e.Site.Spec.HelperImage {
					t.Fatalf("endpoint did not use the independently pinned fixed helper: %#v", container)
				}
				wantArgs := []string{"--url", "https://registry.internal/v2/", "--method", "GET", "--expected-status", "200", "--timeout-seconds", "30", "--ca", "--authorization"}
				if !slices.Equal(container.Args, wantArgs) || job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds != 30 {
					t.Fatalf("endpoint worker arguments or bound changed: %v", container.Args)
				}
				roles := map[string]string{}
				for _, env := range container.Env {
					if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
						if env.Value != "" || env.ValueFrom.SecretKeyRef.Name != "endpoint-materials" {
							t.Fatal("endpoint material did not use its approved Kubernetes Secret reference")
						}
						roles[env.Name] = env.ValueFrom.SecretKeyRef.Key
					}
				}
				if len(roles) != 2 || roles[endpointprobe.CAEnvironment] != "ca" || roles[endpointprobe.AuthorizationEnvironment] != "authorization" {
					t.Fatalf("endpoint material aliases differ from their exact roles: %v", roles)
				}
				if outcome == "failed" {
					job.Status.Conditions[0].Type = batchv1.JobFailed
				}
				if outcome == "lost-ack" {
					if err := client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job.DeepCopy(), "test"); err != nil {
						t.Fatal(err)
					}
					return true, nil, errors.New("lost endpoint worker acknowledgement")
				}
				return false, nil, nil
			})
			result, err := e.Resume(context.Background(), "endpoint-run", v, policy, nil, true)
			if outcome == "pass" {
				if err != nil || result.Acceptance != "pass" || strings.Join(created, ",") != "/usr/local/bin/cinderlock,/bin/true,/bin/true" {
					t.Fatalf("endpoint did not run once before mutation and reuse its original result: %v %v", created, err)
				}
				return
			}
			if err == nil || result.Acceptance == "pass" || result.Domains["workflow"] != "blocked" || strings.Join(created, ",") != "/usr/local/bin/cinderlock" {
				t.Fatalf("failed endpoint crossed application mutation: jobs=%v domains=%v error=%v", created, result.Domains, err)
			}
			if _, err := e.Resume(context.Background(), "endpoint-run", v, policy, nil, true); err == nil || len(created) != 1 {
				t.Fatalf("endpoint resume repeated a failed or unobservable worker: %v %v", created, err)
			}
		})
	}
}

func TestEndpointConstraintsBlockPlanningAndResume(t *testing.T) {
	for _, denied := range []string{"floating-helper", "missing-helper", "host", "site-capability", "policy-capability", "HTTP-site", "HTTP-policy", "missing-secret", "denied-secret", "file-secret", "cross-namespace", "reserved-secret"} {
		t.Run(denied, func(t *testing.T) {
			e, client, policy, p, v := endpointRun(t)
			check := &p.Checks[1]
			switch denied {
			case "floating-helper":
				e.Site.Spec.HelperImage = "helper"
			case "missing-helper":
				e.Site.Spec.HelperImage = "sha256:" + strings.Repeat("e", 64)
			case "host":
				e.Site.Spec.AllowedHosts = []string{"elsewhere.internal"}
			case "site-capability":
				e.Site.Spec.AllowedActions = slices.DeleteFunc(e.Site.Spec.AllowedActions, func(s string) bool { return s == "endpoint-probe" })
			case "policy-capability":
				policy.Spec.AllowedActions = slices.DeleteFunc(policy.Spec.AllowedActions, func(s string) bool { return s == "endpoint-probe" })
				policy.Spec.Epoch++
				admitFixturePolicy(t, e, policy)
			case "HTTP-site", "HTTP-policy":
				check.URL, check.CASecretRef, check.AuthorizationSecretRef, check.SecretRefs = "http://registry.internal/v2/", "", "", nil
				if denied == "HTTP-site" {
					policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "endpoint-http")
					policy.Spec.Epoch++
					admitFixturePolicy(t, e, policy)
				} else {
					e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "endpoint-http")
				}
			case "missing-secret":
				if err := client.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("secrets"), "test", "endpoint-materials"); err != nil {
					t.Fatal(err)
				}
			case "denied-secret":
				client.PrependReactor("get", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
					if action.(ktesting.GetAction).GetName() == "endpoint-materials" {
						return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "endpoint-materials", errors.New("denied"))
					}
					return false, nil, nil
				})
			case "file-secret":
				e.Site.Spec.SecretRefs["header"] = spec.SecretRef{File: "/private/unavailable-endpoint-material"}
			case "cross-namespace":
				e.Site.Spec.SecretRefs["header"] = spec.SecretRef{Name: "endpoint-materials", Key: "authorization", Namespace: "other"}
			case "reserved-secret":
				e.Site.Spec.SecretRefs["cinderlock-run-id"] = e.Site.Spec.SecretRefs["header"]
				delete(e.Site.Spec.SecretRefs, "header")
				check.AuthorizationSecretRef, check.SecretRefs[1] = "cinderlock-run-id", "cinderlock-run-id"
			}
			bindEndpointSite(t, e, &p, policy)
			plan, err := e.Plan(context.Background(), v, p.BundlePath, p.SitePath, policy)
			if err != nil && spec.ExitCode(err) != 16 || err == nil && plan.Executable {
				t.Fatalf("endpoint constraint was not a planning blocker: executable=%v error=%v", plan.Executable, err)
			}
			storeResumePlan(t, e, p, v, "denied-endpoint")
			if _, err := e.Resume(context.Background(), "denied-endpoint", v, policy, nil, true); err == nil {
				t.Fatal("manufactured executable plan bypassed endpoint constraints")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "create" && action.GetResource().Resource == "jobs" {
					t.Fatal("denied endpoint created a worker")
				}
			}
		})
	}
}

func TestEndpointHTTPUsesExplicitCustomerProfile(t *testing.T) {
	e, _, policy, p, v := endpointRun(t)
	check := p.Checks[1]
	check.URL, check.CASecretRef, check.AuthorizationSecretRef, check.SecretRefs = "http://registry.internal/v2/", "", "", nil
	if _, _, _, err := e.endpointJob(check, v); err == nil {
		t.Fatal("HTTP endpoint used an implicit profile")
	}
	e.Site.Spec.AllowedActions = append(e.Site.Spec.AllowedActions, "endpoint-http")
	policy.Spec.AllowedActions = append(policy.Spec.AllowedActions, "endpoint-http")
	p.Checks = []spec.Check{check}
	if _, args, _, err := e.endpointJob(check, v); err != nil || !slices.Contains(args, "--allow-http") || slices.Contains(args, "--authorization") || slices.Contains(args, "--ca") {
		t.Fatalf("approved anonymous HTTP profile was not explicit: args=%v error=%v", args, err)
	}
	e.addExecutionFindings(context.Background(), &p, v, policy)
	if !p.Executable {
		t.Fatalf("approved HTTP profile blocked: %v", p.Findings)
	}
}

func TestEndpointAuthorizationBindsRecipeAndCapabilities(t *testing.T) {
	e, _, policy, p, _ := endpointRun(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy.Spec.Keys = []spec.TrustedKey{{ID: "customer", PublicKey: base64.StdEncoding.EncodeToString(public), Applications: []string{"app"}, Channels: []string{"stable"}, Roles: []string{"approval"}}}
	policy.Spec.Epoch++
	admitFixturePolicy(t, e, policy)
	p.PolicyDigest, p.PolicyEpoch = mustDigest(t, policy), policy.Spec.Epoch
	a := spec.Authorization{Header: spec.NewHeader("Authorization"), PlanDigest: mustDigest(t, p), PlanKind: p.Kind, TargetID: p.Snapshot.TargetID, PolicyDigest: p.PolicyDigest, PolicyEpoch: p.PolicyEpoch, Actions: []string{"migrate", "job", "endpoint-probe"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Nonce: "endpoint-approval"}
	if err := spec.SignAuthorization(&a, private, "customer"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.authorize(p, policy, &a, false); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []string{"job", "endpoint-probe"} {
		missing := a
		missing.Actions = slices.DeleteFunc(slices.Clone(a.Actions), func(s string) bool { return s == capability })
		if err := spec.SignAuthorization(&missing, private, "customer"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.authorize(p, policy, &missing, false); spec.ExitCode(err) != 16 {
			t.Fatalf("signed endpoint authorization omitted %s: %v", capability, err)
		}
	}
	p.Checks = slices.Clone(p.Checks)
	p.Checks[1].URL = "https://another.internal/v2/"
	if _, err := e.authorize(p, policy, &a, false); spec.ExitCode(err) != 16 {
		t.Fatalf("signed endpoint plan accepted a different route: %v", err)
	}
}

func TestEndpointPrerequisitesRevalidateBetweenWorkers(t *testing.T) {
	e, client, policy, p, v := endpointRun(t)
	second := p.Checks[1]
	second.ID, second.URL = "identity-route", "https://registry.internal/ready"
	p.Checks = append(p.Checks, second)
	v.Index.Lock.Release.Spec.Checks = p.Checks
	storeResumePlan(t, e, p, v, "endpoint-boundary")
	created := 0
	client.PrependReactor("create", "jobs", func(action ktesting.Action) (bool, runtime.Object, error) {
		job := action.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		created++
		job.UID = types.UID("uid-" + job.Name)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
		if created == 1 {
			changed := policy
			changed.Spec.Epoch++
			body, err := spec.Canonical(changed)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(e.Site.Spec.TrustPolicy, body, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return false, nil, nil
	})
	if _, err := e.Resume(context.Background(), "endpoint-boundary", v, policy, nil, true); spec.ExitCode(err) != 11 || created != 1 {
		t.Fatalf("a later prerequisite crossed a changed authority boundary: workers=%d error=%v", created, err)
	}
}

func TestEndpointJobPreservesLiteralURLAcrossKubeletExpansion(t *testing.T) {
	e, _, _, p, v := endpointRun(t)
	check := p.Checks[1]
	check.URL = "https://registry.internal/$metadata/$(CINDERLOCK_ENDPOINT_AUTHORIZATION)"
	_, args, _, err := e.endpointJob(check, v)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) < 2 || args[1] != "https://registry.internal/$$metadata/$$(CINDERLOCK_ENDPOINT_AUTHORIZATION)" {
		t.Fatalf("kubelet can expand the signed literal route into request material: %v", args)
	}
}
