package endpointprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
)

func TestRunRejectsInvalidOptions(t *testing.T) {
	_, validCA := testCertificate(t, "127.0.0.1")
	for _, tc := range []struct {
		name   string
		change func(*Options)
	}{
		{"missing URL", func(o *Options) { o.URL = "" }},
		{"scheme", func(o *Options) { o.URL = "ftp://127.0.0.1/private-url-path" }},
		{"userinfo", func(o *Options) { o.URL = "https://private-user:private-password@127.0.0.1/private-url-path" }},
		{"query", func(o *Options) { o.URL += "?private-query=value" }},
		{"empty query", func(o *Options) { o.URL += "?" }},
		{"fragment", func(o *Options) { o.URL += "#private-fragment" }},
		{"malformed URL", func(o *Options) { o.URL += "%private-escape" }},
		{"POST", func(o *Options) { o.Method = http.MethodPost }},
		{"lowercase method", func(o *Options) { o.Method = "get" }},
		{"missing status", func(o *Options) { o.ExpectedStatus = 0 }},
		{"low status", func(o *Options) { o.ExpectedStatus = 99 }},
		{"high status", func(o *Options) { o.ExpectedStatus = 600 }},
		{"negative timeout", func(o *Options) { o.Timeout = -time.Nanosecond }},
		{"long timeout", func(o *Options) { o.Timeout = spec.EndpointMaxTimeoutSeconds*time.Second + time.Nanosecond }},
		{"large CA", func(o *Options) {
			o.CAPEM = append(append([]byte(nil), validCA...), []byte(strings.Repeat("\n", MaxCABytes+1-len(validCA)))...)
		}},
		{"empty supplied CA", func(o *Options) { o.CAPEM = []byte{} }},
		{"invalid CA", func(o *Options) { o.CAPEM = []byte("private-invalid-ca") }},
		{"invalid certificate", func(o *Options) {
			o.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("private-invalid-certificate")})
		}},
		{"large authorization", func(o *Options) { o.Authorization = strings.Repeat("a", MaxAuthorizationBytes+1) }},
		{"leading space", func(o *Options) { o.Authorization = " private-authorization" }},
		{"trailing space", func(o *Options) { o.Authorization = "private-authorization " }},
		{"only whitespace", func(o *Options) { o.Authorization = " \t " }},
		{"HTTP requires opt in", func(o *Options) { o.URL = "http://127.0.0.1:1/private-url-path" }},
		{"HTTP with authorization", func(o *Options) {
			o.URL, o.AllowHTTP, o.Authorization = "http://127.0.0.1:1/private-url-path", true, "private-authorization"
		}},
		{"HTTP with CA", func(o *Options) {
			o.URL, o.AllowHTTP, o.CAPEM = "http://127.0.0.1:1/private-url-path", true, validCA
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{URL: "https://127.0.0.1:1/private-url-path", ExpectedStatus: http.StatusOK}
			tc.change(&opts)
			result, err := Run(context.Background(), opts)
			assertSafeError(t, result, err, 2, opts.URL, "127.0.0.1", "private-url-path", "private-query", "private-user", "private-password", string(opts.CAPEM), opts.Authorization)
			if result.Status != 0 || result.Response != "not_observed" {
				t.Fatalf("invalid options observed a response: %+v", result)
			}
		})
	}
	for b := 0; b <= 255; b++ {
		if b >= 0x20 && b <= 0x7e {
			continue
		}
		t.Run(fmt.Sprintf("authorization byte %02x", b), func(t *testing.T) {
			authorization := "private" + string([]byte{byte(b)}) + "authorization"
			result, err := Run(context.Background(), Options{
				URL: "https://127.0.0.1:1/private-url-path", ExpectedStatus: http.StatusOK, Authorization: authorization,
			})
			assertSafeError(t, result, err, 2, authorization)
		})
	}
	result, err := Run(nil, Options{URL: "https://127.0.0.1:1/private-url-path", ExpectedStatus: http.StatusOK})
	assertSafeError(t, result, err, 2, "127.0.0.1", "private-url-path")
}

func TestRunCanceled(t *testing.T) {
	t.Setenv(CAEnvironment, "private-ambient-ca")
	t.Setenv(AuthorizationEnvironment, "private-ambient-authorization")
	_, ca := testCertificate(t, "127.0.0.1")
	ca = append(ca, []byte(strings.Repeat("\n", MaxCABytes-len(ca)))...)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, opts := range []Options{
		{URL: "http://127.0.0.1:1/private-canceled-path", AllowHTTP: true, ExpectedStatus: 100},
		{URL: "https://127.0.0.1:1/private-canceled-path", ExpectedStatus: 599, Timeout: spec.EndpointMaxTimeoutSeconds * time.Second, CAPEM: ca, Authorization: strings.Repeat("a", MaxAuthorizationBytes)},
	} {
		result, err := Run(ctx, opts)
		assertSafeError(t, result, err, 14, opts.URL, "127.0.0.1", "private-canceled-path", string(ca), opts.Authorization, "private-ambient-ca", "private-ambient-authorization")
		if result.Status != 0 || result.Response != "not_observed" {
			t.Fatalf("canceled request observed a response: %+v", result)
		}
	}
}

func TestTransportIgnoresProxies(t *testing.T) {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(name, "http://127.0.0.1:9")
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	transport := newTransport(t.Context(), nil)
	defer transport.CloseIdleConnections()
	for _, scheme := range []string{"http", "https"} {
		// Evaluate policy for a proxy-eligible hostname without dispatching it.
		req, err := http.NewRequest(http.MethodGet, scheme+"://proxy-eligible.invalid/private-proxy-path", nil)
		if err != nil {
			t.Fatal(err)
		}
		if transport.Proxy != nil {
			proxy, err := transport.Proxy(req)
			t.Fatalf("nonlocal request consulted proxy policy: proxy=%v err=%v", proxy, err)
		}
	}
	if transport.TLSClientConfig.RootCAs != nil {
		t.Fatal("omitting CA material must use platform roots")
	}
}

func assertSafeError(t *testing.T, result Result, err error, code int, private ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a safe error")
	}
	if spec.ExitCode(err) != code || errors.Unwrap(err) != nil {
		t.Fatalf("unexpected error or exposed cause: %#v", err)
	}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	output := fmt.Sprintf("%s %v %+v %#v", encoded, err, err, err)
	for _, value := range private {
		if value != "" && strings.Contains(output, value) {
			t.Fatal("error or result disclosed private material")
		}
	}
}

func TestRunTLS(t *testing.T) {
	const body = "synthetic-private-response-body"
	for _, tc := range []struct {
		name, method, authorization string
		status                      int
		maximum                     bool
	}{
		{"default GET", "", "Opaque synthetic-private-authorization", http.StatusOK, false},
		{"GET without authorization", http.MethodGet, "", http.StatusNoContent, false},
		{"HEAD opaque authorization", http.MethodHead, "opaque-without-a-scheme", http.StatusUnauthorized, false},
		{"maximum material", http.MethodGet, strings.Repeat("a", MaxAuthorizationBytes), 599, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				method := tc.method
				if method == "" {
					method = http.MethodGet
				}
				if r.Method != method || r.Header.Get("Authorization") != tc.authorization {
					t.Error("request did not carry the selected method and authorization")
				}
				values := r.Header.Values("Authorization")
				if len(values) > 1 || (tc.authorization == "" && len(values) != 0) {
					t.Error("unexpected authorization header values")
				}
				if !r.Close || r.ContentLength != 0 {
					t.Error("request allowed connection reuse or carried a body")
				}
				w.WriteHeader(tc.status)
				if method != http.MethodHead && tc.status != http.StatusNoContent {
					fmt.Fprint(w, body)
				}
			}))
			defer server.Close()
			ca := certificatePEM(server)
			opts := Options{URL: server.URL, Method: tc.method, ExpectedStatus: tc.status, CAPEM: ca, Authorization: tc.authorization}
			if tc.maximum {
				opts.CAPEM = append(ca, []byte(strings.Repeat("\n", MaxCABytes-len(ca)))...)
				opts.Timeout = spec.EndpointMaxTimeoutSeconds * time.Second
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			result, err := Run(ctx, opts)
			if err != nil {
				t.Fatal(err)
			}
			authorization := "not_supplied"
			if tc.authorization != "" {
				authorization = "supplied"
			}
			if want := (Result{Status: tc.status, Response: "observed", Authorization: authorization}); result != want {
				t.Fatalf("result = %+v, want %+v", result, want)
			}
			if requests.Load() != 1 {
				t.Fatal("worker did not make exactly one request")
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{server.URL, string(ca), tc.authorization, body} {
				if private != "" && strings.Contains(string(encoded), private) {
					t.Fatal("result disclosed private material")
				}
			}
		})
	}
}

func TestRunHTTPDoesNotReadEnvironmentMaterial(t *testing.T) {
	t.Setenv(CAEnvironment, "private-invalid-environment-ca")
	t.Setenv(AuthorizationEnvironment, "private-environment-authorization")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || len(r.Header.Values("Authorization")) != 0 {
			t.Error("HTTP request used ambient authorization or an unexpected method")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	result, err := Run(t.Context(), Options{URL: server.URL, AllowHTTP: true, ExpectedStatus: http.StatusNoContent, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if want := (Result{Status: http.StatusNoContent, Response: "observed", Authorization: "not_supplied"}); result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
}

func TestRunTLSFailures(t *testing.T) {
	wrongHostname, _ := testCertificate(t, "different-endpoint.test")
	untrustedCertificate, wrongCA := testCertificate(t, "127.0.0.1")
	for _, mode := range []string{"platform roots", "wrong CA", "hostname", "TLS version", "plain HTTP"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			switch mode {
			case "platform roots":
				server.TLS = &tls.Config{Certificates: []tls.Certificate{untrustedCertificate}}
			case "hostname":
				server.TLS = &tls.Config{Certificates: []tls.Certificate{wrongHostname}}
			case "TLS version":
				server.TLS = &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11}
			}
			var ca []byte
			if mode == "plain HTTP" {
				server.Start()
			} else {
				server.StartTLS()
				ca = certificatePEM(server)
			}
			defer server.Close()
			if mode == "platform roots" {
				ca = nil
			} else if mode == "wrong CA" {
				ca = wrongCA
			}
			const authorization = "private-tls-authorization"
			url := strings.Replace(server.URL, "http://", "https://", 1) + "/private-tls-path"
			result, err := Run(t.Context(), Options{URL: url, ExpectedStatus: http.StatusOK, CAPEM: ca, Authorization: authorization, Timeout: 2 * time.Second})
			assertSafeError(t, result, err, 14, url, "127.0.0.1", "private-tls-path", "different-endpoint.test", string(ca), authorization)
			if want := (Result{Response: "not_observed", Authorization: "supplied"}); result != want {
				t.Fatalf("result = %+v, want %+v", result, want)
			}
			if requests.Load() != 0 {
				t.Fatal("TLS failure sent an HTTP request")
			}
		})
	}
}

func TestRunRejectsRedirects(t *testing.T) {
	var forwarded atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
	}))
	defer destination.Close()
	var requests atomic.Int32
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		status, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Location", destination.URL+"/private-redirect-path?private-redirect-query=value")
		w.Header().Set("Content-Length", "1099511627776")
		w.WriteHeader(status)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer source.Close()
	defer source.CloseClientConnections()
	ca := certificatePEM(source)
	for status := 300; status < 400; status++ {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			const authorization = "private-redirect-authorization"
			result, err := Run(t.Context(), Options{
				URL: source.URL + "/" + strconv.Itoa(status), ExpectedStatus: status, CAPEM: ca, Authorization: authorization, Timeout: 2 * time.Second,
			})
			assertSafeError(t, result, err, 14, source.URL, destination.URL, string(ca), authorization, "private-redirect-path", "private-redirect-query")
			if want := (Result{Status: status, Response: "observed", Authorization: "supplied"}); result != want {
				t.Fatalf("result = %+v, want %+v", result, want)
			}
		})
	}
	if requests.Load() != 100 || forwarded.Load() != 0 {
		t.Fatalf("requests = %d, redirected requests = %d", requests.Load(), forwarded.Load())
	}
}

func TestRunStatusMismatch(t *testing.T) {
	const body = "private-status-response-body"
	const authorization = "private-status-authorization"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		fmt.Fprint(w, body)
	}))
	defer server.Close()
	ca := certificatePEM(server)
	url := server.URL + "/private-status-path"
	result, err := Run(t.Context(), Options{URL: url, ExpectedStatus: http.StatusOK, CAPEM: ca, Authorization: authorization, Timeout: 2 * time.Second})
	assertSafeError(t, result, err, 14, url, "127.0.0.1", "private-status-path", string(ca), authorization, body)
	if want := (Result{Status: http.StatusTeapot, Response: "observed", Authorization: "supplied"}); result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
}

func TestRunRejectsLargeResponseHeaders(t *testing.T) {
	const privateHeader = "private-response-header"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Private", strings.Repeat(privateHeader, (32<<10)/len(privateHeader)+1))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	result, err := Run(t.Context(), Options{URL: server.URL, AllowHTTP: true, ExpectedStatus: http.StatusOK, Timeout: 2 * time.Second})
	assertSafeError(t, result, err, 14, server.URL, privateHeader)
	if want := (Result{Response: "not_observed", Authorization: "not_supplied"}); result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
}

func TestRunHeaderTimeoutAndCancellation(t *testing.T) {
	for _, mode := range []string{"worker timeout", "context deadline", "context cancellation"} {
		t.Run(mode, func(t *testing.T) {
			seen, closed := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(seen)
				<-r.Context().Done()
				close(closed)
			}))
			defer server.Close()
			defer server.CloseClientConnections()
			parentTimeout := 2 * time.Second
			workerTimeout := 2 * time.Second
			if mode == "worker timeout" {
				workerTimeout = 250 * time.Millisecond
			} else if mode == "context deadline" {
				parentTimeout = 250 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), parentTimeout)
			defer cancel()
			if mode == "context cancellation" {
				go func() {
					select {
					case <-seen:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			start := time.Now()
			result, err := Run(ctx, Options{URL: server.URL + "/private-timeout-path", AllowHTTP: true, ExpectedStatus: http.StatusOK, Timeout: workerTimeout})
			assertSafeError(t, result, err, 14, server.URL, "127.0.0.1", "private-timeout-path")
			if result.Status != 0 || result.Response != "not_observed" || time.Since(start) >= 1500*time.Millisecond {
				t.Fatalf("request was not bounded before observing headers: %+v", result)
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("cancellation did not close the server connection")
			}
		})
	}
}

func TestRunTLSHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted, closed := make(chan net.Conn, 1), make(chan struct{})
	go func() {
		defer close(closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		accepted <- conn
		_, _ = io.Copy(io.Discard, conn)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	const authorization = "private-handshake-authorization"
	url := "https://" + listener.Addr().String() + "/private-handshake-path"
	start := time.Now()
	result, err := Run(ctx, Options{URL: url, ExpectedStatus: http.StatusOK, Authorization: authorization, Timeout: 250 * time.Millisecond})
	var conn net.Conn
	select {
	case conn = <-accepted:
		defer conn.Close()
	default:
		t.Fatal("test did not reach the TLS handshake")
	}
	assertSafeError(t, result, err, 14, url, "127.0.0.1", "private-handshake-path", authorization)
	if result.Status != 0 || result.Response != "not_observed" || time.Since(start) >= 1500*time.Millisecond {
		t.Fatalf("TLS handshake was not bounded: %+v", result)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("TLS timeout left the connection open")
	}
}

func TestRunDoesNotReadResponseBody(t *testing.T) {
	for _, mode := range []string{"huge content length", "infinite stream", "invalid gzip", "protocol upgrade"} {
		t.Run(mode, func(t *testing.T) {
			const body = "private-stream-response-body"
			closed := make(chan struct{})
			status := http.StatusOK
			if mode == "protocol upgrade" {
				status = http.StatusSwitchingProtocols
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "huge content length" {
					w.Header().Set("Content-Length", "1099511627776")
				} else if mode == "invalid gzip" {
					w.Header().Set("Content-Encoding", "gzip")
				}
				if mode == "protocol upgrade" {
					w.Header().Set("Connection", "Upgrade")
					w.Header().Set("Upgrade", "private-upgrade-protocol")
				}
				w.WriteHeader(status)
				if status != http.StatusSwitchingProtocols {
					fmt.Fprint(w, body)
				}
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				close(closed)
			}))
			defer server.Close()
			defer server.CloseClientConnections()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type outcome struct {
				result Result
				err    error
			}
			done := make(chan outcome, 1)
			ca := certificatePEM(server)
			const authorization = "private-stream-authorization"
			go func() {
				result, err := Run(ctx, Options{URL: server.URL, ExpectedStatus: status, CAPEM: ca, Authorization: authorization, Timeout: 5 * time.Second})
				done <- outcome{result, err}
			}()
			select {
			case got := <-done:
				if got.err != nil {
					t.Fatal(got.err)
				}
				if want := (Result{Status: status, Response: "observed", Authorization: "supplied"}); got.result != want {
					t.Fatalf("result = %+v, want %+v", got.result, want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("worker waited for the response body")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("worker left the streaming response open")
			}
		})
	}
}

func certificatePEM(server *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
}

func testCertificate(t *testing.T, hostname string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
