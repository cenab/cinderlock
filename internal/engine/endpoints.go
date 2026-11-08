package engine

import (
	"slices"
	"strconv"
	"strings"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
)

func (e *Engine) endpointJob(check spec.Check, verified *bundle.Verified) ([]string, []string, *jobOptions, error) {
	if check.Type != "endpoint" {
		return nil, nil, nil, spec.Err(2, "fixed endpoint worker requires an endpoint check")
	}
	if err := spec.ValidateCheck(check); err != nil {
		return nil, nil, nil, err
	}
	if !spec.ValidDigest(e.Site.Spec.HelperImage) {
		return nil, nil, nil, spec.Err(16, "endpoint checks require an independently admitted exact helper digest")
	}
	if _, err := e.image(verified, e.Site.Spec.HelperImage); err != nil {
		return nil, nil, nil, spec.Err(10, "endpoint helper digest is not available among locked images")
	}
	u, err := spec.ParseEndpointURL(check.URL)
	if err != nil {
		return nil, nil, nil, err
	}
	if !slices.Contains(e.Site.Spec.AllowedHosts, u.Hostname()) {
		return nil, nil, nil, spec.Err(16, "endpoint destination is not in the customer host allowlist")
	}
	for _, capability := range spec.EndpointActions([]spec.Check{check}) {
		if !slices.Contains(e.Site.Spec.AllowedActions, capability) {
			return nil, nil, nil, spec.Err(16, "endpoint prerequisite capability is not admitted by the Site")
		}
	}
	method := check.Method
	if method == "" {
		method = "GET"
	}
	timeout := check.TimeoutSeconds
	if timeout == 0 {
		timeout = spec.EndpointDefaultTimeoutSeconds
	}
	// Kubelet expands dollar references in argv; the approved URL stays literal.
	args := []string{"--url", strings.ReplaceAll(check.URL, "$", "$$"), "--method", method, "--expected-status", strconv.Itoa(check.ExpectedStatus), "--timeout-seconds", strconv.FormatInt(timeout, 10)}
	if check.CASecretRef != "" {
		args = append(args, "--ca")
	}
	if check.AuthorizationSecretRef != "" {
		args = append(args, "--authorization")
	}
	if u.Scheme == "http" {
		args = append(args, "--allow-http")
	}
	return []string{"/usr/local/bin/cinderlock", "helper", "endpoint-probe"}, args, &jobOptions{Endpoint: &check}, nil
}
