package spec

import (
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// GitOpsProfileContract selects one fixed, read-only controller adapter.
type GitOpsProfileContract struct {
	Header
	Profile          string                  `json:"profile"`
	Namespace        string                  `json:"namespace"`
	Name             string                  `json:"name"`
	UID              string                  `json:"uid"`
	Repository       string                  `json:"repository"`
	RepositoryURL    string                  `json:"repositoryURL"`
	AcceptedRevision string                  `json:"acceptedRevision"`
	ManifestDigest   string                  `json:"manifestDigest"`
	NotBefore        string                  `json:"notBefore"`
	MaxAgeSeconds    int64                   `json:"maxAgeSeconds"`
	InstallationID   string                  `json:"installationID,omitempty"`
	Reversion        *GitOpsProfileReversion `json:"reversion,omitempty"`
}

// GitOpsProfileReversion selects historical revisions of the same tracked file.
type GitOpsProfileReversion struct {
	PreviousRevision string `json:"previousRevision"`
	RestoredRevision string `json:"restoredRevision"`
}

var gitOpsIdentityToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

// ValidateGitOpsProfileContract checks the fixed profile against current server time.
func ValidateGitOpsProfileContract(c GitOpsProfileContract, now time.Time) error {
	if strings.ContainsAny(c.Repository, "\x00\r\n") || strings.Contains(c.Repository, "://") {
		return Err(2, "GitOps profile requires a local repository directory")
	}
	for _, part := range strings.Split(c.Repository, "/") {
		if part == ".." {
			return Err(2, "GitOps profile repository directory cannot contain a path escape")
		}
	}
	u, err := url.Parse(c.RepositoryURL)
	if ValidateHeader(c.Header, "GitOpsProfileContract") != nil || c.Profile != "argocd-directory-v1" || len(validation.IsDNS1123Label(c.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(c.Name)) != 0 || !ValidGitOpsIdentity(c.UID) || c.Repository == "" || err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(c.RepositoryURL, "\\#\r\n\t") || !ValidGitOpsCommit(c.AcceptedRevision) || !ValidDigest(c.ManifestDigest) || c.MaxAgeSeconds <= 0 || c.MaxAgeSeconds > 86400 || c.InstallationID != "" && !ValidGitOpsIdentity(c.InstallationID) {
		return Err(2, "invalid or unsupported GitOps profile contract")
	}
	before, err := time.Parse(time.RFC3339Nano, c.NotBefore)
	if err != nil || before.IsZero() || before.After(now) {
		return Err(2, "GitOps profile requires a valid nonfuture notBefore timestamp")
	}
	if c.Reversion != nil && (!ValidGitOpsCommit(c.Reversion.PreviousRevision) || !ValidGitOpsCommit(c.Reversion.RestoredRevision)) {
		return Err(2, "GitOps profile reversion requires full lower-case commit IDs")
	}
	return nil
}

// ValidGitOpsIdentity accepts bounded metadata tokens retained in GitOps evidence.
func ValidGitOpsIdentity(value string) bool { return gitOpsIdentityToken.MatchString(value) }

// ValidGitOpsCommit accepts full lower-case SHA-1 or SHA-256 commit identifiers.
func ValidGitOpsCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
