package catalog

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	Issuer   string           `json:"issuer"`
	ClientID string           `json:"clientID"`
	Subjects map[string]Actor `json:"subjects"`
}

type OIDCVerifier struct {
	verifier *oidc.IDTokenVerifier
	subjects map[string]Actor
	scope    string
}

// NewOIDC uses only the explicitly configured internal issuer; no public fallback exists.
func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDCVerifier, error) {
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || cfg.ClientID == "" || len(cfg.Subjects) == 0 {
		return nil, errors.New("OIDC requires an explicit HTTPS issuer, client ID and subject bindings")
	}
	copySubjects := map[string]Actor{}
	for sub, a := range cfg.Subjects {
		if sub == "" {
			return nil, errors.New("invalid OIDC subject binding")
		}
		if err := validateActor(a, false); err != nil {
			return nil, err
		}
		copySubjects[sub] = cloneActor(a)
	}
	client := http.DefaultClient
	if custom, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && custom != nil {
		client = custom
	}
	bounded := *client
	if bounded.Timeout == 0 || bounded.Timeout > 30*time.Second {
		bounded.Timeout = 30 * time.Second
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if t, ok := transport.(*http.Transport); ok {
		copy := t.Clone()
		copy.Proxy = nil
		transport = copy
	}
	bounded.Transport = issuerTransport{base: transport, host: u.Host}
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("OIDC redirects require a new explicit issuer configuration")
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, &bounded), cfg.Issuer)
	if err != nil {
		return nil, err
	}
	b, err := canonical(struct {
		Issuer   string           `json:"issuer"`
		ClientID string           `json:"clientID"`
		Subjects map[string]Actor `json:"subjects"`
	}{cfg.Issuer, cfg.ClientID, copySubjects})
	if err != nil {
		return nil, err
	}
	return &OIDCVerifier{verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}), subjects: copySubjects, scope: digestBytes(b)}, nil
}

type issuerTransport struct {
	base http.RoundTripper
	host string
}

func (t issuerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != t.host {
		return nil, errors.New("OIDC endpoint is outside the admitted issuer host")
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	response.Body = http.MaxBytesReader(nil, response.Body, MaxObjectBytes)
	return response, nil
}

func (v *OIDCVerifier) Verify(ctx context.Context, raw string) (Actor, error) {
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return Actor{}, errors.New("OIDC token verification rejected")
	}
	actor, ok := v.subjects[token.Subject]
	if !ok {
		return Actor{}, errors.New("OIDC subject has no admitted role binding")
	}
	return cloneActor(actor), nil
}
