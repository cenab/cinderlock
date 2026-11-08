# Endpoint prerequisites from the worker network

An `endpoint` check observes one declared HTTP response from its actual helper
Job's network context. It is a required prerequisite before application mutation,
using the same approved plan, worker identity, and no-duplicate journal as other
checks. The [contract](../internal/spec/endpoint.go) and
[worker](../internal/endpointprobe/) define the supported profile.

> **Note:** This is a preview feature currently under active development.

## Declare an existing endpoint

Endpoint prerequisites must already exist independently of the release being
applied, such as an internal registry or identity service. Use application
post-deployment checks for services this release will create. An endpoint check
must explicitly declare `domain: readiness` and `required: true`; it cannot
replace a required application workflow.

This fragment belongs in a complete Release's `checks` list:

```yaml
- id: registry-response
  type: endpoint
  domain: readiness
  required: true
  url: https://registry.internal/v2/
  method: GET
  expectedStatus: 200
  timeoutSeconds: 30
  caSecretRef: route-ca
  authorizationSecretRef: route-authorization
  secretRefs: [route-ca, route-authorization]
```

The fixed adapter rejects authored images, commands, script contracts, fixtures,
body matching, and nonzero expected exits. It supports GET and HEAD over HTTP/1.1.
URLs cannot contain userinfo, query strings, or fragments. Redirects fail even
when their status was declared as expected; no redirected destination is reached.

## Bind customer authority and material

The private Site must admit the exact helper image manifest digest through
`helperImage`, include the destination hostname in `allowedHosts`, and bind each
material reference to an explicit Kubernetes Secret name/key in the target
namespace. The helper digest must also exist among the bundle's locked images.
The admitted helper image must contain this version of the native worker.

Both Site and TrustPolicy must permit `job` and `endpoint-probe`. A signed
execution authorization also names those capabilities and binds the exact plan.
Plain HTTP additionally requires `endpoint-http` in Site, policy, and signed
authorization, and cannot use CA or authorization material. This is an explicit
customer profile choice, never an inferred fallback from failed HTTPS.

Optional `caSecretRef` and `authorizationSecretRef` must be distinct and listed
exactly in `secretRefs`; extra material is rejected. The engine maps them to fixed
worker environment aliases through Kubernetes Secret references. Reference names
cannot override execution provenance, proxy configuration, or TLS environment
settings. No credential values enter the plan, command arguments, or result.
Local credential files and automatic token retrieval are unsupported.

Supplied CA certificates replace the worker's platform trust roots for this
request. Without a CA reference, the admitted helper's platform roots apply.
Authorization is an opaque header value and requires HTTPS. The worker verifies
TLS normally, ignores ambient proxies, makes one request, reads no response body,
and closes the connection. Request time, headers, CA material, and authorization
input are bounded. Errors omit URLs, material, and response contents.

## Interpret the observation

A successful worker exit means the original endpoint returned the declared
nonredirect status. Its safe output records `response: observed`, the status,
and whether authorization was supplied. A response such as HTTP 200 does not
establish that credentials, license rights, or every application route are valid.

Approved artifact imports may run first so the helper can be materialized. The
helper image and target must be available before its Job can start. An image-pull
or scheduling failure is not an observed HTTP response and does not prove node
pull credentials are current. Planning never starts a probe Job.

Between individual prerequisite workers and after a prerequisite wait, the
engine rechecks approval, policy, coordination, target state, and secret bindings
before following work. URLs remain literal through Kubernetes argument handling.
Resume reuses the original Job UID and recipe; failed or uncertain workers are
never blindly repeated. Resolve the original worker and use a separately
authorized supported recovery or new attempt when needed. Changed material
requires new binding review, not reuse of an old checkpoint.

This is one retained observation from one Job context, not continuous endpoint
health, fresh node pull authorization, DNS tracing, full route coverage, network
independence, or proof of physical isolation. Loopback worker tests and fake
Kubernetes clients do not qualify transport from a real cluster namespace.
