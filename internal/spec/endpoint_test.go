package spec

import (
	"reflect"
	"strings"
	"testing"
)

func endpointCheck() Check {
	return Check{ID: "registry-route", Type: "endpoint", Domain: "readiness", Required: true, URL: "https://registry.internal/v2/", ExpectedStatus: 200, CASecretRef: "corp-ca", AuthorizationSecretRef: "header", SecretRefs: []string{"corp-ca", "header"}}
}

func TestEndpointContractRejectsIgnoredOrUnsafeInputs(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Check)
		valid  bool
	}{
		{"TLS-material", func(c *Check) {}, true},
		{"anonymous-HTTP", func(c *Check) {
			c.URL = "http://registry.internal/v2/"
			c.CASecretRef, c.AuthorizationSecretRef, c.SecretRefs = "", "", nil
		}, true},
		{"HEAD", func(c *Check) { c.Method = "HEAD" }, true},
		{"maximum-timeout", func(c *Check) { c.TimeoutSeconds = EndpointMaxTimeoutSeconds }, true},
		{"optional", func(c *Check) { c.Required = false }, false},
		{"workflow", func(c *Check) { c.Domain = "workflow" }, false},
		{"image", func(c *Check) { c.Image = "vendor-image" }, false},
		{"command", func(c *Check) { c.Command = []string{"/vendor/script"} }, false},
		{"script", func(c *Check) { c.Script = checkContract(c.ID) }, false},
		{"observations", func(c *Check) { c.ObservationContract = &ObservationContract{} }, false},
		{"fixtures", func(c *Check) { c.Fixtures = []string{"fixture"} }, false},
		{"body", func(c *Check) { c.BodyContains = "private-body-sentinel" }, false},
		{"synthetic-data", func(c *Check) { c.SyntheticData = "private-data-sentinel" }, false},
		{"exit", func(c *Check) { c.ExpectedExitCode = 1 }, false},
		{"method", func(c *Check) { c.Method = "POST" }, false},
		{"status", func(c *Check) { c.ExpectedStatus = 0 }, false},
		{"negative-timeout", func(c *Check) { c.TimeoutSeconds = -1 }, false},
		{"long-timeout", func(c *Check) { c.TimeoutSeconds = EndpointMaxTimeoutSeconds + 1 }, false},
		{"userinfo", func(c *Check) { c.URL = "https://private-user:private-password@registry.internal/" }, false},
		{"query", func(c *Check) { c.URL += "?private-query=value" }, false},
		{"empty-query", func(c *Check) { c.URL += "?" }, false},
		{"fragment", func(c *Check) { c.URL += "#private-fragment" }, false},
		{"empty-fragment", func(c *Check) { c.URL += "#" }, false},
		{"scheme", func(c *Check) { c.URL = "file:///private-file" }, false},
		{"missing-role", func(c *Check) { c.SecretRefs = []string{"corp-ca"} }, false},
		{"extra-role", func(c *Check) { c.SecretRefs = append(c.SecretRefs, "other") }, false},
		{"duplicate-role", func(c *Check) { c.SecretRefs = []string{"header", "header"} }, false},
		{"shared-role", func(c *Check) { c.CASecretRef = "header"; c.SecretRefs = []string{"header"} }, false},
		{"invalid-role", func(c *Check) { c.CASecretRef = "private invalid role" }, false},
		{"HTTP-authorization", func(c *Check) { c.URL = "http://registry.internal/v2/" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			check := endpointCheck()
			test.change(&check)
			err := ValidateCheck(check)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
			if err != nil {
				for _, private := range []string{"private-user", "private-password", "private-query", "private-fragment", "private-body-sentinel", "private-data-sentinel"} {
					if strings.Contains(err.Error(), private) {
						t.Fatal("contract error disclosed private input")
					}
				}
			}
		})
	}
	legacy := Check{ID: "http", Type: "http", Domain: "workflow", URL: "http://app/health?existing=query", ExpectedStatus: 200, BodyContains: "existing literal"}
	if err := ValidateCheck(legacy); err != nil {
		t.Fatal("existing fixed HTTP adapter changed:", err)
	}
	legacy.AuthorizationSecretRef = "header"
	if err := ValidateCheck(legacy); err == nil {
		t.Fatal("endpoint credential role was silently ignored by another adapter")
	}
}

func TestEndpointActionsAndRequiredWorkflowRemainDistinct(t *testing.T) {
	check := endpointCheck()
	if got := EndpointActions([]Check{check}); !reflect.DeepEqual(got, []string{"job", "endpoint-probe"}) {
		t.Fatal(got)
	}
	check.URL, check.CASecretRef, check.AuthorizationSecretRef, check.SecretRefs = "http://registry.internal/", "", "", nil
	if got := EndpointActions([]Check{check, check}); !reflect.DeepEqual(got, []string{"job", "endpoint-probe", "endpoint-http"}) {
		t.Fatal(got)
	}
	r := classifiedScriptRelease()
	r.Spec.Checks = append(r.Spec.Checks, endpointCheck())
	if err := ValidateRelease(r); err != nil {
		t.Fatal(err)
	}
	r.Spec.Operations[0].Script.SuccessChecks = []string{"registry-route"}
	if err := ValidateRelease(r); err == nil {
		t.Fatal("endpoint readiness was used as application success evidence")
	}
}
