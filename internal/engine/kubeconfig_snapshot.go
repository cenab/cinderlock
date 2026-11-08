package engine

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const maxKubeconfigBytes = 4 << 20

// readKubernetesInput captures a bounded regular file through one descriptor.
// A pipe, device or leaf symlink cannot stall or redirect credential loading.
func readKubernetesInput(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open Kubernetes configuration input")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("Kubernetes configuration input must be a bounded regular file without group or world writes")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("cannot capture bounded Kubernetes configuration input")
	}
	return data, nil
}

func captureKubernetesConfig(raw *clientcmdapi.Config, filename, contextName, namespace string) ([]byte, error) {
	raw.CurrentContext = contextName
	if err := clientcmdapi.MinifyConfig(raw); err != nil {
		return nil, errors.New("cannot select explicit Kubernetes configuration")
	}
	selected := raw.Contexts[contextName]
	selected.Namespace = namespace
	cluster, auth := raw.Clusters[selected.Cluster], raw.AuthInfos[selected.AuthInfo]
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, errors.New("cannot resolve Kubernetes configuration directory")
	}
	base := filepath.Dir(abs)
	flatten := func(path *string, data *[]byte) error {
		if *path == "" {
			return nil
		}
		if len(*data) != 0 {
			return errors.New("Kubernetes TLS material cannot specify both a file and embedded data")
		}
		captured, err := readKubernetesInput(clientcmdapi.ResolvePath(*path, base), 1<<20)
		if err != nil {
			return errors.New("cannot capture referenced Kubernetes TLS material")
		}
		*data = captured
		*path = ""
		return nil
	}
	for _, input := range []struct {
		path *string
		data *[]byte
	}{{&cluster.CertificateAuthority, &cluster.CertificateAuthorityData}, {&auth.ClientCertificate, &auth.ClientCertificateData}, {&auth.ClientKey, &auth.ClientKeyData}} {
		if err := flatten(input.path, input.data); err != nil {
			return nil, err
		}
	}
	if auth.TokenFile != "" {
		if auth.Token != "" {
			return nil, errors.New("Kubernetes authentication cannot combine token and rotating tokenFile")
		}
		token, err := readKubernetesInput(clientcmdapi.ResolvePath(auth.TokenFile, base), 64<<10)
		if err != nil {
			return nil, errors.New("cannot capture referenced Kubernetes token")
		}
		auth.Token = strings.TrimSpace(string(token))
		if auth.Token == "" {
			return nil, errors.New("captured Kubernetes token is empty")
		}
		auth.TokenFile = ""
	}
	// All file content has already passed the bounded descriptor reader. Use the
	// SDK's flattening contract without permitting any further filesystem reads.
	if err := clientcmdapi.FlattenConfig(raw); err != nil {
		return nil, errors.New("cannot flatten selected Kubernetes configuration")
	}
	raw.Extensions = nil
	raw.Preferences.Extensions = nil
	selected.Extensions, cluster.Extensions, auth.Extensions = nil, nil, nil
	snapshot, err := clientcmd.Write(*raw)
	if err != nil || len(snapshot) > 8<<20 {
		return nil, errors.New("cannot serialize bounded selected Kubernetes configuration")
	}
	return snapshot, nil
}

func (k *Kubernetes) writeConfigSnapshot(work string) (string, error) {
	if k == nil || len(k.configSnapshot) == 0 {
		return "", errors.New("Helm requires the captured Kubernetes configuration")
	}
	path := filepath.Join(work, "kubeconfig")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", errors.New("cannot prepare private captured Kubernetes configuration")
	}
	_, writeErr := f.Write(k.configSnapshot)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return "", errors.New("cannot write private captured Kubernetes configuration")
	}
	return path, nil
}
