package spec

import (
	"net/url"
	"strings"
)

const EndpointDefaultTimeoutSeconds = 30
const EndpointMaxTimeoutSeconds = 120

// ParseEndpointURL excludes portable credentials before target planning or a
// worker can use the URL. Its errors never include the supplied URL.
func ParseEndpointURL(raw string) (*url.URL, error) {
	if len(raw) > 4096 {
		return nil, Err(2, "endpoint URL exceeds the supported limit")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, Err(2, "endpoint URL requires an explicit HTTP(S) host without userinfo, query, or fragment")
	}
	return u, nil
}

func validateEndpointCheck(c Check) error {
	if c.Domain != "readiness" || !c.Required {
		return Err(2, "endpoint checks must declare readiness and required: true")
	}
	if c.Image != "" || len(c.Command) != 0 || c.Script != nil || len(c.Fixtures) != 0 || c.BodyContains != "" || c.SyntheticData != "" || c.ExpectedExitCode != 0 {
		return Err(2, "endpoint checks use only the fixed helper without authored commands, images, scripts, fixtures, or body matching")
	}
	if c.TimeoutSeconds > EndpointMaxTimeoutSeconds {
		return Err(2, "endpoint timeout exceeds the supported maximum")
	}
	u, err := ParseEndpointURL(c.URL)
	if err != nil {
		return err
	}
	if c.Method != "" && c.Method != "GET" && c.Method != "HEAD" || c.ExpectedStatus < 100 || c.ExpectedStatus > 599 {
		return Err(2, "endpoint checks require GET or HEAD and an explicit expected status")
	}
	roles := map[string]bool{}
	for _, ref := range []string{c.CASecretRef, c.AuthorizationSecretRef} {
		if ref == "" {
			continue
		}
		if !identifier.MatchString(ref) || roles[ref] {
			return Err(2, "endpoint CA and authorization roles require distinct valid secret references")
		}
		roles[ref] = true
	}
	if len(c.SecretRefs) != len(roles) {
		return Err(2, "endpoint secretRefs must contain exactly its CA and authorization references")
	}
	seen := map[string]bool{}
	for _, ref := range c.SecretRefs {
		if !roles[ref] || seen[ref] {
			return Err(2, "endpoint secretRefs must contain exactly its distinct role references")
		}
		seen[ref] = true
	}
	if u.Scheme == "http" && len(roles) != 0 {
		return Err(2, "endpoint HTTP cannot use CA or authorization material")
	}
	return nil
}

// EndpointActions names the customer capabilities needed by fixed endpoint
// prerequisites, including explicit acceptance of HTTP without credentials.
func EndpointActions(checks []Check) []string {
	var actions []string
	for _, check := range checks {
		if check.Type != "endpoint" {
			continue
		}
		if len(actions) == 0 {
			actions = []string{"job", "endpoint-probe"}
		}
		if u, err := ParseEndpointURL(check.URL); err == nil && u.Scheme == "http" && !containsString(actions, "endpoint-http") {
			actions = append(actions, "endpoint-http")
		}
	}
	return actions
}
