package spec

import (
	"path/filepath"
	"strings"
)

// ResolveSitePaths preserves explicit inputs while resolving private file references.
// The caller selects any default state directory separately.
func ResolveSitePaths(site Site, base string) Site {
	resolve := func(value string) string {
		if value == "" || filepath.IsAbs(value) {
			return value
		}
		return filepath.Join(base, value)
	}
	site.Spec.Kubeconfig = resolve(site.Spec.Kubeconfig)
	site.Spec.TrustPolicy = resolve(site.Spec.TrustPolicy)
	site.Spec.RegistryCAFile = resolve(site.Spec.RegistryCAFile)
	site.Spec.StateDir = resolve(site.Spec.StateDir)
	site.Spec.StorageOperatorPath = resolve(site.Spec.StorageOperatorPath)
	site.Spec.HardwareEvidence = resolve(site.Spec.HardwareEvidence)
	if strings.Contains(site.Spec.HelmPath, string(filepath.Separator)) {
		site.Spec.HelmPath = resolve(site.Spec.HelmPath)
	}
	if site.Spec.SecretRefs != nil {
		refs := make(map[string]SecretRef, len(site.Spec.SecretRefs))
		for key, ref := range site.Spec.SecretRefs {
			ref.File = resolve(ref.File)
			refs[key] = ref
		}
		site.Spec.SecretRefs = refs
	}
	return site
}
