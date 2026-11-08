package endpointprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

const (
	CAEnvironment            = "CINDERLOCK_ENDPOINT_CA_PEM"
	AuthorizationEnvironment = "CINDERLOCK_ENDPOINT_AUTHORIZATION"
	MaxCABytes               = 64 << 10
	MaxAuthorizationBytes    = 16 << 10
)

type Options struct {
	URL            string
	Method         string
	ExpectedStatus int
	Timeout        time.Duration
	AllowHTTP      bool
	CAPEM          []byte
	Authorization  string
}

type Result struct {
	Status        int    `json:"status"`
	Response      string `json:"response"`
	Authorization string `json:"authorization"`
}

// Run observes one endpoint's status without reading its response body.
func Run(ctx context.Context, opts Options) (Result, error) {
	result := Result{Response: "not_observed", Authorization: "not_supplied"}
	if opts.Authorization != "" {
		result.Authorization = "supplied"
	}
	u, err := spec.ParseEndpointURL(opts.URL)
	if err != nil {
		return result, err
	}
	if opts.Method == "" {
		opts.Method = http.MethodGet
	}
	if opts.Method != http.MethodGet && opts.Method != http.MethodHead {
		return result, spec.Err(2, "endpoint method must be GET or HEAD")
	}
	if opts.ExpectedStatus < 100 || opts.ExpectedStatus > 599 {
		return result, spec.Err(2, "endpoint expected status must be between 100 and 599")
	}
	if opts.Timeout == 0 {
		opts.Timeout = spec.EndpointDefaultTimeoutSeconds * time.Second
	}
	if opts.Timeout < 0 || opts.Timeout > spec.EndpointMaxTimeoutSeconds*time.Second {
		return result, spec.Err(2, "endpoint timeout is outside the supported range")
	}
	if len(opts.CAPEM) > MaxCABytes {
		return result, spec.Err(2, "endpoint CA material exceeds the supported limit")
	}
	if len(opts.Authorization) > MaxAuthorizationBytes || strings.TrimSpace(opts.Authorization) != opts.Authorization {
		return result, spec.Err(2, "endpoint authorization value is invalid")
	}
	for i := 0; i < len(opts.Authorization); i++ {
		if opts.Authorization[i] < 0x20 || opts.Authorization[i] > 0x7e {
			return result, spec.Err(2, "endpoint authorization value is invalid")
		}
	}
	if u.Scheme == "http" && (!opts.AllowHTTP || opts.CAPEM != nil || opts.Authorization != "") {
		return result, spec.Err(2, "endpoint HTTP requires explicit permission and no TLS or authorization material")
	}
	var roots *x509.CertPool
	if opts.CAPEM != nil {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(opts.CAPEM) {
			return result, spec.Err(2, "endpoint CA material must contain a certificate")
		}
	}
	if ctx == nil {
		return result, spec.Err(2, "endpoint context is required")
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, opts.Method, u.String(), nil)
	if err != nil {
		return result, spec.Err(2, "endpoint request is invalid")
	}
	if opts.Authorization != "" {
		req.Header.Set("Authorization", opts.Authorization)
	}
	response, err := newTransport(ctx, roots).RoundTrip(req)
	if err != nil {
		return result, spec.Err(14, "endpoint request failed")
	}
	result.Status = response.StatusCode
	result.Response = "observed"
	// Cancel the raw connection before Close, including for protocol upgrades.
	cancel()
	_ = response.Body.Close()
	if result.Status >= 300 && result.Status < 400 {
		return result, spec.Err(14, "endpoint redirects are not allowed")
	}
	if result.Status != opts.ExpectedStatus {
		return result, spec.Err(14, "endpoint status did not match expected status")
	}
	return result, nil
}

func newTransport(ctx context.Context, roots *x509.CertPool) *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Transport{
		Proxy:                  nil,
		Protocols:              protocols,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		MaxResponseHeaderBytes: 32 << 10,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			// Transport detaches its dial context; retain the request's bound.
			conn, err := new(net.Dialer).DialContext(ctx, network, address)
			if err == nil {
				context.AfterFunc(ctx, func() { _ = conn.Close() })
			}
			return conn, err
		},
	}
}
