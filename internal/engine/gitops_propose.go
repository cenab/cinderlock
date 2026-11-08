package engine

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cenab/cinderlock/internal/bundle"
	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
)

const maxGitOpsFileBytes = 1 << 20

var gitOpsSourcePath = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
var gitOpsConfigInclude = regexp.MustCompile(`(?im)^\s*\[\s*include`)

type GitOpsSourceChange struct {
	Repository     string `json:"repository"`
	Head           string `json:"head"`
	Path           string `json:"path"`
	BaseBlob       string `json:"baseBlob"`
	BaseDigest     string `json:"baseDigest"`
	ManifestDigest string `json:"manifestDigest"`
	PatchDigest    string `json:"patchDigest"`
	Patch          string `json:"patch"`
}

type GitOpsProposal struct {
	spec.Header
	Owner                 string             `json:"owner"`
	BundleDigest          string             `json:"bundleDigest"`
	SiteDigest            string             `json:"siteDigest"`
	SourceSiteDigest      string             `json:"sourceSiteDigest"`
	PolicyDigest          string             `json:"policyDigest"`
	Source                GitOpsSourceChange `json:"source"`
	ApplicationAcceptance string             `json:"applicationAcceptance"`
	Notice                string             `json:"notice"`
}

func gitOpsCommitID(value string) bool {
	if len(value) != 40 && len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func gitOpsTargetPath(value string) bool {
	if !fs.ValidPath(value) || !gitOpsSourcePath.MatchString(value) || len(value) > 4096 || strings.Count(value, "/") > 63 {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if strings.EqualFold(part, ".git") {
			return false
		}
	}
	return filepath.Ext(value) == ".yaml" || filepath.Ext(value) == ".yml"
}

func openGitOpsDirectory(name string) (*os.Root, string, error) {
	if name == "" {
		return nil, "", spec.Err(2, "GitOps directory must be explicit")
	}
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return nil, "", spec.Err(2, "GitOps directory contains a path escape")
		}
	}
	absolute, err := filepath.Abs(name)
	if err != nil {
		return nil, "", err
	}
	for parent := absolute; ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, "", spec.Err(2, "GitOps directories must be real directories without symlink ancestors")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	before, err := os.Lstat(absolute)
	if err != nil {
		return nil, "", err
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, "", err
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, "", spec.Err(11, "GitOps directory changed while opening")
	}
	return root, absolute, nil
}

func readGitOpsFile(root *os.Root, name string) ([]byte, error) {
	parts := strings.Split(name, "/")
	current := root
	var opened []*os.Root
	defer func() {
		for _, child := range opened {
			_ = child.Close()
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		before, err := current.Lstat(part)
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return nil, spec.Err(2, "GitOps source path has an unsafe directory")
		}
		child, err := current.OpenRoot(part)
		if err != nil {
			return nil, err
		}
		opened = append(opened, child)
		after, err := child.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			return nil, spec.Err(11, "GitOps source directory changed")
		}
		current = child
	}
	base := parts[len(parts)-1]
	before, err := current.Lstat(base)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > maxGitOpsFileBytes {
		return nil, spec.Err(2, "GitOps input must be a bounded regular file without symlinks")
	}
	f, err := current.OpenFile(base, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) {
		return nil, spec.Err(11, "GitOps input changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(f, maxGitOpsFileBytes+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || len(body) > maxGitOpsFileBytes || int64(len(body)) != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || after.Mode() != before.Mode() {
		return nil, spec.Err(11, "GitOps input changed or exceeded its limit")
	}
	return body, nil
}

type gitOpsRepository struct {
	root           *os.Root
	directory, git string
}

func (repo gitOpsRepository) read(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	base := []string{"--no-pager", "--no-optional-locks", "--no-replace-objects", "--no-lazy-fetch", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull, "-c", "core.attributesFile=" + os.DevNull, "-c", "diff.external=", "--git-dir=" + filepath.Join(repo.directory, ".git"), "--work-tree=" + repo.directory}
	command := exec.CommandContext(ctx, repo.git, append(base, args...)...)
	command.Dir = repo.directory
	command.Env = []string{"PATH=" + filepath.Dir(repo.git), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "LANG=C", "LC_ALL=C"}
	stdout, stderr := &limitedBuffer{limit: maxGitOpsFileBytes}, &limitedBuffer{limit: 16 << 10}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		return nil, spec.Err(10, "local Git read failed or requires an unsupported Git capability")
	}
	return stdout.Bytes(), nil
}

func gitOpsRecord(data []byte) ([]string, error) {
	if bytes.Count(data, []byte{0}) != 1 || len(data) == 0 || data[len(data)-1] != 0 {
		return nil, spec.Err(11, "GitOps target is missing or has ambiguous index/tree records")
	}
	metadata, path, ok := strings.Cut(string(data[:len(data)-1]), "\t")
	parts := strings.Fields(metadata)
	if !ok || len(parts) != 3 {
		return nil, spec.Err(11, "GitOps target record is malformed")
	}
	return append(parts, path), nil
}

func (repo gitOpsRepository) snapshot(ctx context.Context, head, target string) (string, []byte, error) {
	actual, err := repo.read(ctx, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", nil, err
	}
	if strings.TrimSpace(string(actual)) != head {
		return "", nil, spec.Err(11, "GitOps repository HEAD differs from the reviewed commit")
	}
	kind, err := repo.read(ctx, "cat-file", "-t", head)
	if err != nil || strings.TrimSpace(string(kind)) != "commit" {
		return "", nil, spec.Err(11, "GitOps expected revision is not an exact local commit")
	}
	tree, err := repo.read(ctx, "ls-tree", "-z", head, "--", target)
	if err != nil {
		return "", nil, err
	}
	tracked, err := gitOpsRecord(tree)
	if err != nil {
		return "", nil, err
	}
	index, err := repo.read(ctx, "ls-files", "--stage", "-z", "--", target)
	if err != nil {
		return "", nil, err
	}
	staged, err := gitOpsRecord(index)
	if err != nil {
		return "", nil, err
	}
	if tracked[0] != "100644" || tracked[1] != "blob" || tracked[3] != target || staged[0] != "100644" || staged[1] != tracked[2] || staged[2] != "0" || staged[3] != target {
		return "", nil, spec.Err(11, "GitOps target must be the clean exact regular HEAD/index file")
	}
	for _, args := range [][]string{{"check-attr", "--source=" + head, "--all", "-z", "--", target}, {"check-attr", "--cached", "--all", "-z", "--", target}, {"check-attr", "--all", "-z", "--", target}} {
		attributes, err := repo.read(ctx, args...)
		if err != nil {
			return "", nil, err
		}
		if len(attributes) != 0 {
			return "", nil, spec.Err(10, "GitOps target attributes, filters, and diff drivers require a separately supported profile")
		}
	}
	size, err := repo.read(ctx, "cat-file", "-s", tracked[2])
	if err != nil {
		return "", nil, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(size)), 10, 64)
	if err != nil || n < 0 || n > maxGitOpsFileBytes {
		return "", nil, spec.Err(2, "GitOps HEAD file exceeds the bounded text profile")
	}
	body, err := repo.read(ctx, "cat-file", "blob", tracked[2])
	if err != nil {
		return "", nil, err
	}
	working, err := readGitOpsFile(repo.root, target)
	if err != nil {
		return "", nil, err
	}
	workingInfo, err := repo.root.Lstat(target)
	if err != nil || !workingInfo.Mode().IsRegular() || workingInfo.Mode().Perm()&0111 != 0 {
		return "", nil, spec.Err(11, "GitOps working target has an unsafe file type or changed executable mode")
	}
	if int64(len(body)) != n || !bytes.Equal(body, working) {
		return "", nil, spec.Err(11, "GitOps working target differs from the exact HEAD/index bytes")
	}
	if !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return "", nil, spec.Err(2, "GitOps source is binary or invalid UTF-8")
	}
	return tracked[2], body, nil
}

// ProposeGitOpsSource never changes the index, files, refs, or remote repository.
func ProposeGitOpsSource(ctx context.Context, repository, head, target string, desired []byte) (GitOpsSourceChange, error) {
	var out GitOpsSourceChange
	if !gitOpsCommitID(head) || !gitOpsTargetPath(target) || len(desired) == 0 || len(desired) > maxGitOpsFileBytes || !utf8.Valid(desired) || bytes.IndexByte(desired, 0) >= 0 {
		return out, spec.Err(2, "GitOps proposal requires an exact commit, confined YAML path, and bounded text manifest")
	}
	root, directory, err := openGitOpsDirectory(repository)
	if err != nil {
		return out, err
	}
	defer root.Close()
	// shortcut: embedded Git directories only; qualify linked worktrees and object stores before widening.
	for _, name := range []string{".git", ".git/objects"} {
		info, err := root.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return out, spec.Err(10, "GitOps proposal requires an embedded real Git directory")
		}
	}
	for _, name := range []string{".git/commondir", ".git/objects/info/alternates", ".git/info/grafts", ".git/info/attributes"} {
		if _, err := root.Lstat(name); err == nil || !os.IsNotExist(err) {
			return out, spec.Err(10, "GitOps repository has unsupported alternate objects, grafts, or private attributes")
		}
	}
	for _, name := range []string{".git/config", ".git/HEAD", ".git/index"} {
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return out, spec.Err(10, "GitOps metadata must be regular files without symlinks")
		}
	}
	for _, name := range []string{".git/config", ".git/config.worktree"} {
		if _, err := root.Lstat(name); os.IsNotExist(err) {
			continue
		}
		data, err := readGitOpsFile(root, name)
		if err != nil || gitOpsConfigInclude.Match(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})) {
			return out, spec.Err(10, "GitOps configuration includes or unsafe config files are unsupported")
		}
	}
	if _, err := readGitOpsFile(root, target); err != nil {
		return out, err
	}
	for parent := filepath.Dir(target); ; parent = filepath.Dir(parent) {
		if _, err := root.Lstat(filepath.ToSlash(filepath.Join(parent, ".gitattributes"))); err == nil || !os.IsNotExist(err) {
			return out, spec.Err(10, "GitOps working-tree attributes are outside the supported profile")
		}
		if parent == "." {
			break
		}
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return out, spec.Err(10, "an installed local Git executable is required")
	}
	repo := gitOpsRepository{root: root, directory: directory, git: git}
	blob, before, err := repo.snapshot(ctx, head, target)
	if err != nil {
		return out, err
	}
	patch := ""
	if !bytes.Equal(before, desired) {
		// shortcut: replace one complete text file; add minimal hunks if whole-file review becomes unwieldy.
		rangeOf := func(data []byte) string {
			n := bytes.Count(data, []byte{'\n'})
			if len(data) > 0 && data[len(data)-1] != '\n' {
				n++
			}
			if n == 0 {
				return "0,0"
			}
			return fmt.Sprintf("1,%d", n)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n@@ -%s +%s @@\n", target, target, target, target, rangeOf(before), rangeOf(desired))
		for _, part := range []struct {
			prefix string
			data   []byte
		}{{"-", before}, {"+", desired}} {
			for _, line := range bytes.SplitAfter(part.data, []byte{'\n'}) {
				if len(line) == 0 {
					continue
				}
				b.WriteString(part.prefix)
				b.Write(line)
				if line[len(line)-1] != '\n' {
					b.WriteString("\n\\ No newline at end of file\n")
				}
			}
		}
		patch = b.String()
	}
	afterBlob, after, err := repo.snapshot(ctx, head, target)
	if err != nil {
		return out, err
	}
	if blob != afterBlob || !bytes.Equal(before, after) {
		return out, spec.Err(11, "GitOps source changed while preparing the proposal")
	}
	return GitOpsSourceChange{Repository: directory, Head: head, Path: target, BaseBlob: blob, BaseDigest: spec.Hash(before), ManifestDigest: spec.Hash(desired), PatchDigest: spec.Hash([]byte(patch)), Patch: patch}, nil
}

// GitOpsPreparationPath requires an existing parent outside the source repository.
func GitOpsPreparationPath(repository, selected string) (string, error) {
	root, _, err := openGitOpsDirectory(repository)
	if err != nil {
		return "", err
	}
	defer root.Close()
	absolute, err := filepath.Abs(selected)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", spec.Err(2, "GitOps preparation output requires an existing parent directory")
	}
	resolved := filepath.Join(parent, filepath.Base(absolute))
	if info, err := os.Lstat(resolved); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", spec.Err(2, "GitOps preparation path cannot be a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	repositoryInfo, err := root.Stat(".")
	if err != nil {
		return "", err
	}
	// File identity also detects case aliases on case-insensitive filesystems.
	for parent := resolved; ; parent = filepath.Dir(parent) {
		info, err := os.Stat(parent)
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if err == nil && os.SameFile(repositoryInfo, info) {
			return "", spec.Err(16, "GitOps preparation state and proposal output must be outside the source repository")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return resolved, nil
}

func (e *Engine) ProposeGitOps(ctx context.Context, v *bundle.Verified, policy spec.TrustPolicy, sitePath, repository, head, target, manifestPath, approvedManifestDigest string) (GitOpsProposal, error) {
	var out GitOpsProposal
	r := v.Index.Lock.Release
	if err := spec.ValidateRelease(r); err != nil {
		return out, err
	}
	if err := spec.ValidatePolicy(policy); err != nil {
		return out, err
	}
	policyDigest, err := spec.Digest(policy)
	if err != nil {
		return out, err
	}
	currentPolicy := func() error {
		var current spec.TrustPolicy
		if err := spec.Read(e.Site.Spec.TrustPolicy, &current); err != nil {
			return err
		}
		actual, err := spec.Digest(current)
		if err != nil || actual != policyDigest {
			return spec.Err(11, "trust policy changed during GitOps proposal creation")
		}
		return spec.ValidatePolicy(current)
	}
	if err = currentPolicy(); err != nil {
		return out, err
	}
	declared := r.Spec.Deployment.GitOps
	if r.Spec.Deployment.Type != "gitops" || declared == nil || (declared.Owner != "flux" && declared.Owner != "argocd") || declared.Revision != head || declared.Path != target || !gitOpsCommitID(head) || e.Site.Spec.Profile != r.Spec.Profile {
		return out, spec.Err(10, "GitOps proposal differs from its signed owner, exact base revision, path, or Site profile")
	}
	if _, err := GitOpsPreparationPath(repository, e.StateDir); err != nil {
		return out, err
	}
	manifestParent, err := filepath.EvalSymlinks(filepath.Dir(manifestPath))
	if err != nil {
		return out, err
	}
	parent, _, err := openGitOpsDirectory(manifestParent)
	if err != nil {
		return out, err
	}
	desired, err := readGitOpsFile(parent, filepath.Base(manifestPath))
	_ = parent.Close()
	if err != nil {
		return out, err
	}
	if !spec.ValidDigest(approvedManifestDigest) || spec.Hash(desired) != approvedManifestDigest {
		return out, spec.Err(11, "reviewed manifest digest does not match its exact input bytes")
	}
	source, err := sourceSiteDigest(sitePath)
	if err != nil {
		return out, err
	}
	rendered, err := e.RenderDesiredState(ctx, v)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(rendered, desired) {
		return out, spec.Err(11, "reviewed manifest differs from the verified bundle and selected Site render")
	}
	change, err := ProposeGitOpsSource(ctx, repository, head, target, desired)
	if err != nil {
		return out, err
	}
	current, err := sourceSiteDigest(sitePath)
	if err != nil || current != source {
		return out, spec.Err(11, "Site source changed during GitOps proposal creation")
	}
	if err = currentPolicy(); err != nil {
		return out, err
	}
	siteDigest, err := spec.Digest(e.Site)
	if err != nil {
		return out, err
	}
	out = GitOpsProposal{Header: spec.NewHeader("GitOpsProposal"), Owner: declared.Owner, BundleDigest: v.Digest, SiteDigest: siteDigest, SourceSiteDigest: source, PolicyDigest: policyDigest, Source: change, ApplicationAcceptance: "not_established", Notice: "Local source proposal only; no repository file, index, commit, remote, or application resource was changed. Controller reconciliation, model/data delivery, application workflows, hooks, and data recovery remain unqualified."}
	out.Metadata = r.Metadata
	return out, nil
}

func WriteGitOpsProposal(output string, proposal GitOpsProposal) error {
	path, err := GitOpsPreparationPath(proposal.Source.Repository, output)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	before, err := os.Stat(directory)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return spec.Err(11, "GitOps proposal output directory changed")
	}
	body, err := spec.Canonical(proposal)
	if err != nil {
		return err
	}
	name := filepath.Base(path)
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = root.Remove(name)
		}
	}()
	if _, err = f.Write(append(body, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
