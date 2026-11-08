package engine

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestKubernetesIgnoresUnadmittedEnvironmentProxy(t *testing.T) {
	if os.Getenv("CINDERLOCK_PROXY_TEST_CHILD") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(executable, "-test.run=^TestKubernetesIgnoresUnadmittedEnvironmentProxy$")
		cmd.Env = append(os.Environ(), "CINDERLOCK_PROXY_TEST_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("direct-route check failed: %v\n%s", err, output)
		}
		return
	}
	var proxyRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"major":"1","minor":"35","gitVersion":"v1.35.0"}`))
	}))
	defer server.Close()
	leaf, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil || len(leaf.DNSNames) == 0 {
		t.Fatal("test TLS certificate lacks a server name")
	}
	raw := clientcmdapi.Config{Clusters: map[string]*clientcmdapi.Cluster{"cluster": {Server: "https://cluster.cinderlock.invalid", TLSServerName: leaf.DNSNames[0], CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})}}, AuthInfos: map[string]*clientcmdapi.AuthInfo{"user": {Token: "synthetic-test-token"}}, Contexts: map[string]*clientcmdapi.Context{"explicit": {Cluster: "cluster", AuthInfo: "user"}}}
	body, err := clientcmd.Write(raw)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	kube, err := NewKubernetes(path, "explicit", "test", "app")
	if err != nil {
		t.Fatal(err)
	}
	kube.Config.Timeout = 3 * time.Second
	kube.Config.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "cluster.cinderlock.invalid:443" {
			address = server.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	client, err := kubernetes.NewForConfig(kube.Config)
	if err != nil {
		t.Fatal(err)
	}
	version, err := client.Discovery().ServerVersion()
	if err != nil || version.GitVersion != "v1.35.0" || proxyRequests.Load() != 0 {
		t.Fatalf("configured direct target did not remain direct: proxyRequests=%d error=%v", proxyRequests.Load(), err)
	}
}

func TestHelmUsesCapturedKubeconfigAfterOriginalTargetAndAuthChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	initial := []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: cluster\n  cluster:\n    server: https://original.invalid\ncontexts:\n- name: explicit\n  context:\n    cluster: cluster\n    user: user\nusers:\n- name: user\n  user:\n    token: original-token\n")
	if err := os.WriteFile(path, initial, 0600); err != nil {
		t.Fatal(err)
	}
	kube, err := NewKubernetes(path, "explicit", "test", "app")
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.ReplaceAll(initial, []byte("https://original.invalid"), []byte("https://changed.invalid"))
	changed = bytes.ReplaceAll(changed, []byte("token: original-token"), []byte("exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /unapproved/plugin\n      interactiveMode: Never"))
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	parsed := inspectSnapshotWithHelm(t, kube, dir, path)
	if parsed.Clusters["cluster"].Server != kube.Config.Host || parsed.AuthInfos["user"].Exec != nil || parsed.AuthInfos["user"].Token != "original-token" {
		t.Fatal("Helm reloaded a changed target or unapproved credentials after client-go capture")
	}
}

func inspectSnapshotWithHelm(t *testing.T, kube *Kubernetes, dir, source string) *clientcmdapi.Config {
	t.Helper()
	script := []byte("#!/bin/sh\nconfig=\"\"\ncontext=\"\"\nnamespace=\"\"\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in --kubeconfig) shift; config=$1;; --kube-context) shift; context=$1;; --namespace) shift; namespace=$1;; esac\n  shift\ndone\nmode=$(/bin/ls -ld \"$config\")\nmode=${mode%% *}\nprintf '%s\\n%s\\n%s\\n%s\\n%s\\n' \"$config\" \"$KUBECONFIG\" \"$mode\" \"$context\" \"$namespace\"\n/bin/cat \"$config\"\n")
	executable := filepath.Join(dir, "helm-probe")
	if err := os.WriteFile(executable, script, 0700); err != nil {
		t.Fatal(err)
	}
	// Changing Site fields cannot make this captured client use a new selection.
	e := &Engine{Site: spec.Site{Spec: spec.SiteSpec{HelmPath: executable, HelmDigest: spec.Hash(script), Kubeconfig: source, Context: "changed", Namespace: "changed"}}, StateDir: dir, Kube: kube}
	output, err := e.helm(context.Background(), "history", "app")
	if err != nil {
		t.Fatal(err)
	}
	parts := bytes.SplitN(output, []byte{'\n'}, 6)
	if len(parts) != 6 {
		t.Fatal("fake executable did not inspect configuration argument")
	}
	parsed, err := clientcmd.Load(parts[5])
	if err != nil {
		t.Fatal("captured configuration is not usable")
	}
	if string(parts[0]) == source || !bytes.Equal(parts[0], parts[1]) {
		t.Fatal("Helm must receive one private captured file through argument and environment")
	}
	if _, err := os.Stat(string(parts[0])); !os.IsNotExist(err) {
		t.Fatal("temporary credential snapshot was retained after subprocess completion")
	}
	if strings.TrimSuffix(string(parts[2]), "@") != "-rw-------" || string(parts[3]) != kube.Context || string(parts[4]) != kube.Namespace {
		t.Fatalf("Helm captured configuration permissions or selection differ: mode=%q context=%q namespace=%q", parts[2], parts[3], parts[4])
	}
	return parsed
}

func TestReferencedKubernetesCredentialsAreFrozenForClientsAndHelm(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer captured-token" {
			t.Error("client-go reloaded changed credential bytes")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"major":"1","minor":"35","gitVersion":"v1.35.0"}`))
	}))
	defer server.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.TLS.Certificates[0].Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(server.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	leaf, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil || len(leaf.DNSNames) == 0 {
		t.Fatal("test TLS certificate lacks a server name")
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{"ca.pem": cert, "client.pem": cert, "client.key": key, "token": []byte("captured-token\n")} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw := clientcmdapi.Config{Clusters: map[string]*clientcmdapi.Cluster{"cluster": {Server: server.URL, CertificateAuthority: "ca.pem", TLSServerName: leaf.DNSNames[0], DisableCompression: true}, "unused": {Server: "https://unused.invalid"}}, AuthInfos: map[string]*clientcmdapi.AuthInfo{"user": {TokenFile: "token", ClientCertificate: "client.pem", ClientKey: "client.key"}, "unused": {Exec: &clientcmdapi.ExecConfig{Command: "/unselected/plugin"}}}, Contexts: map[string]*clientcmdapi.Context{"explicit": {Cluster: "cluster", AuthInfo: "user", Namespace: "unused-default"}, "unused": {Cluster: "unused", AuthInfo: "unused"}}}
	body, err := clientcmd.Write(raw)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	kube, err := NewKubernetes(path, "explicit", "test", "app")
	if err != nil {
		t.Fatal(err)
	}
	if kube.Config.BearerTokenFile != "" || kube.Config.CAFile != "" || kube.Config.CertFile != "" || kube.Config.KeyFile != "" || kube.Config.BearerToken != "captured-token" || !bytes.Equal(kube.Config.CAData, cert) || !bytes.Equal(kube.Config.CertData, cert) || !bytes.Equal(kube.Config.KeyData, key) || kube.Config.ServerName != leaf.DNSNames[0] || !kube.Config.DisableCompression {
		t.Fatal("client-go retained mutable credential references or lost selected TLS settings")
	}
	for _, name := range []string{"ca.pem", "client.pem", "client.key", "token"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("replaced"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := kube.Client.Discovery().ServerVersion(); err != nil {
		t.Fatalf("static TLS client depended on changed inputs: %v", err)
	}
	parsed := inspectSnapshotWithHelm(t, kube, dir, path)
	if len(parsed.Clusters) != 1 || len(parsed.AuthInfos) != 1 || len(parsed.Contexts) != 1 || parsed.CurrentContext != "explicit" || parsed.Contexts["explicit"].Namespace != "test" {
		t.Fatal("snapshot retained an unselected configuration")
	}
	cluster, auth := parsed.Clusters["cluster"], parsed.AuthInfos["user"]
	if cluster.Server != kube.Config.Host || cluster.TLSServerName != kube.Config.ServerName || !cluster.DisableCompression || cluster.CertificateAuthority != "" || !bytes.Equal(cluster.CertificateAuthorityData, cert) || auth.TokenFile != "" || auth.Token != "captured-token" || auth.ClientCertificate != "" || auth.ClientKey != "" || !bytes.Equal(auth.ClientCertificateData, cert) || !bytes.Equal(auth.ClientKeyData, key) {
		t.Fatal("Helm did not receive the same frozen TLS and credential bytes as client-go")
	}
}

func TestKubernetesSnapshotRejectsUnboundedOrIndirectInputsWithoutLeakingData(t *testing.T) {
	for _, scenario := range []string{"malformed", "oversized", "symlink", "pipe", "writable", "token-symlink", "token-oversized", "token-empty", "token-dual", "tls-conflict"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config")
			raw := clientcmdapi.Config{Clusters: map[string]*clientcmdapi.Cluster{"cluster": {Server: "https://original.invalid"}}, AuthInfos: map[string]*clientcmdapi.AuthInfo{"user": {Token: "secret-sentinel"}}, Contexts: map[string]*clientcmdapi.Context{"explicit": {Cluster: "cluster", AuthInfo: "user"}}}
			if strings.HasPrefix(scenario, "token-") {
				raw.AuthInfos["user"].Token = ""
				raw.AuthInfos["user"].TokenFile = "token"
			}
			switch scenario {
			case "token-symlink":
				if err := os.WriteFile(filepath.Join(dir, "real-token"), []byte("secret-sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("real-token", filepath.Join(dir, "token")); err != nil {
					t.Fatal(err)
				}
			case "token-oversized":
				if err := os.WriteFile(filepath.Join(dir, "token"), bytes.Repeat([]byte{'x'}, 64<<10+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "token-empty":
				if err := os.WriteFile(filepath.Join(dir, "token"), []byte(" \n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "token-dual":
				raw.AuthInfos["user"].Token = "secret-sentinel"
			case "tls-conflict":
				raw.Clusters["cluster"].CertificateAuthority = "secret-sentinel"
				raw.Clusters["cluster"].CertificateAuthorityData = []byte("embedded")
			}
			body, err := clientcmd.Write(raw)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "malformed" {
				body = []byte("token: [secret-sentinel\n")
			}
			if scenario == "oversized" {
				body = bytes.Repeat([]byte{'x'}, maxKubeconfigBytes+1)
			}
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "symlink":
				if err := os.Rename(path, path+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+"-real", path); err != nil {
					t.Fatal(err)
				}
			case "pipe":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			}
			_, err = NewKubernetes(path, "explicit", "test", "app")
			if err == nil {
				t.Fatal("unsupported mutable configuration input was accepted")
			}
			if strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatal("configuration error exposed credential input")
			}
		})
	}
}
