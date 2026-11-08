package catalog

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestOIDCUsesAdmittedIssuerAudienceAndSubject(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.RWMutex
	kid := "initial"
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			mu.RLock()
			defer mu.RUnlock()
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": base64.RawURLEncoding.EncodeToString(private.PublicKey.N.Bytes()), "e": "AQAB"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()
	ctx := oidc.ClientContext(context.Background(), issuer.Client())
	startup, cancel := context.WithCancel(ctx)
	v, err := NewOIDC(startup, OIDCConfig{Issuer: issuer.URL, ClientID: "cinderlock", Subjects: map[string]Actor{"known": {ID: "engineer", Projects: map[string][]string{"plant": {"operator"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	token := func(aud, sub string, expires int64) string {
		mu.RLock()
		defer mu.RUnlock()
		h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
		c, _ := json.Marshal(map[string]any{"iss": issuer.URL, "aud": aud, "sub": sub, "iat": time.Now().Unix(), "exp": expires})
		signed := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
		sum := sha256.Sum256([]byte(signed))
		signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	actor, err := v.Verify(ctx, token("cinderlock", "known", time.Now().Add(time.Hour).Unix()))
	if err != nil || actor.ID != "engineer" {
		t.Fatalf("valid internal token: %v", err)
	}
	for _, bad := range []string{token("other-app", "known", time.Now().Add(time.Hour).Unix()), token("cinderlock", "unknown", time.Now().Add(time.Hour).Unix()), token("cinderlock", "known", time.Now().Add(-time.Hour).Unix())} {
		if _, err = v.Verify(ctx, bad); err == nil {
			t.Fatal("unadmitted token accepted")
		}
	}
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	private = rotated
	kid = "rotated"
	mu.Unlock()
	if _, err = v.Verify(ctx, token("cinderlock", "known", time.Now().Add(time.Hour).Unix())); err != nil {
		t.Fatalf("JWKS refresh after startup cancellation: %v", err)
	}
	if _, err = NewOIDC(ctx, OIDCConfig{Issuer: issuer.URL, ClientID: "cinderlock", Subjects: map[string]Actor{"known": {ID: "engineer", Projects: map[string][]string{"plant": {"typo-role"}}}}}); err == nil {
		t.Fatal("unknown OIDC role admitted")
	}
	if _, err = NewOIDC(ctx, OIDCConfig{Issuer: "http://issuer.invalid", ClientID: "cinderlock", Subjects: map[string]Actor{"known": actor}}); err == nil {
		t.Fatal("plaintext production issuer accepted")
	}
}
