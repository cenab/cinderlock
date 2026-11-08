package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type dockerAuth struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Auth          string `json:"auth,omitempty"`
	Email         string `json:"email,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
	RegistryToken string `json:"registrytoken,omitempty"`
}
type dockerConfig struct {
	Auths map[string]dockerAuth `json:"auths"`
}

func (e *Engine) registryOptions(ctx context.Context) (bundle.RegistryOptions, error) {
	opts := bundle.RegistryOptions{PlainHTTP: e.Site.Spec.RegistryPlainHTTP, CAFile: e.Site.Spec.RegistryCAFile, AllowedAuthHosts: e.Site.Spec.RegistryAuthHosts}
	if e.Site.Spec.RegistryAuthRef == "" {
		return opts, nil
	}
	ref, ok := e.Site.Spec.SecretRefs[e.Site.Spec.RegistryAuthRef]
	if !ok {
		return opts, spec.Err(10, "registry authentication reference is missing")
	}
	var data []byte
	if ref.File != "" {
		info, err := os.Lstat(ref.File)
		if err != nil {
			return opts, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
			return opts, spec.Err(16, "registry credentials must be a private regular file below one MiB")
		}
		f, err := os.Open(ref.File)
		if err != nil {
			return opts, err
		}
		data, err = io.ReadAll(io.LimitReader(f, 1<<20+1))
		_ = f.Close()
		if err != nil {
			return opts, err
		}
	} else {
		ns := ref.Namespace
		if ns == "" {
			ns = e.Site.Spec.Namespace
		}
		if ns != e.Site.Spec.Namespace {
			return opts, spec.Err(16, "cross-namespace registry credentials are unsupported")
		}
		secret, err := e.Kube.Client.CoreV1().Secrets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			return opts, spec.Err(10, "registry credential Secret is unavailable")
		}
		key := ref.Key
		if key == "" {
			key = ".dockerconfigjson"
		}
		data = secret.Data[key]
		if len(data) == 0 || len(data) > 1<<20 {
			return opts, spec.Err(10, "registry credential key missing or exceeds one MiB")
		}
	}
	var config dockerConfig
	if err := spec.Decode(data, &config); err != nil {
		return opts, spec.Err(2, "registry Docker configuration is malformed or uses an unsupported credential-helper format")
	}
	host := strings.SplitN(e.Site.Spec.Registry, "/", 2)[0]
	var selected *dockerAuth
	for _, key := range []string{host, "https://" + host, "http://" + host} {
		if value, ok := config.Auths[key]; ok {
			if selected != nil {
				return opts, spec.Err(2, "registry Docker configuration has ambiguous matching entries")
			}
			entry := value
			selected = &entry
		}
	}
	if selected == nil {
		return opts, spec.Err(10, "registry Docker configuration has no entry for the approved destination")
	}
	if selected.IdentityToken != "" || selected.RegistryToken != "" {
		return opts, spec.Err(10, "registry token credential profile is not qualified")
	}
	opts.Username = selected.Username
	opts.Password = selected.Password
	if selected.Auth != "" {
		decoded, err := base64.StdEncoding.DecodeString(selected.Auth)
		if err != nil {
			return opts, errors.New("invalid registry auth encoding")
		}
		user, password, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return opts, errors.New("invalid registry auth format")
		}
		if opts.Username != "" && (opts.Username != user || opts.Password != password) {
			return opts, errors.New("registry credential fields conflict")
		}
		opts.Username = user
		opts.Password = password
	}
	if opts.Username == "" || opts.Password == "" {
		return opts, spec.Err(10, "registry username/password credential is incomplete")
	}
	return opts, nil
}
