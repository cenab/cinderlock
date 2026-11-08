package discover

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
)

type Finding struct {
	File           string `json:"file"`
	Line           int    `json:"line"`
	Kind           string `json:"kind"`
	Host           string `json:"host,omitempty"`
	Confidence     string `json:"confidence"`
	EvidenceDigest string `json:"evidenceDigest"`
	Suggestion     string `json:"suggestion"`
}
type Report struct {
	ProposalPath  string    `json:"proposalPath,omitempty"`
	ProposalCount int       `json:"proposalCount,omitempty"`
	APIVersion    string    `json:"apiVersion"`
	Kind          string    `json:"kind"`
	Files         int       `json:"files"`
	Findings      []Finding `json:"findings"`
	Coverage      []string  `json:"coverage"`
}

var externalURL = regexp.MustCompile(`https?://[^\s"'<>\x60]+`)
var packageDownload = regexp.MustCompile(`(?i)(pip[3]? install|npm (install|ci)|apt(-get)? install|snapshot_download|from_pretrained|hf_hub_download|nltk.download|spacy download|trust_remote_code)`)

func Scan(ctx context.Context, root string) (Report, error) {
	r := Report{APIVersion: spec.APIVersion, Kind: "DiscoveryReport", Findings: []Finding{}, Coverage: []string{"Static text patterns only; not proof of runtime dependency or complete closure", "Source contents and URL credentials are not included in findings"}}
	root, e := filepath.Abs(root)
	if e != nil {
		return r, e
	}
	total := int64(0)
	e = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if d.IsDir() {
			if p != root && (d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		name := filepath.Base(p)
		if name != "Dockerfile" && name != "Containerfile" && !strings.Contains("|.yaml|.yml|.toml|.json|.py|.js|.ts|.sh|.env|.txt|.conf|.ini|", "|"+ext+"|") {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if info.Size() > 1<<20 {
			return nil
		}
		total += info.Size()
		if r.Files >= 10000 || total > 64<<20 {
			return fmt.Errorf("source scan limit exceeded")
		}
		r.Files++
		f, e := os.Open(p)
		if e != nil {
			return e
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		line := 0
		rel, _ := filepath.Rel(root, p)
		for scanner.Scan() {
			line++
			text := scanner.Text()
			for _, raw := range externalURL.FindAllString(text, -1) {
				u, e := url.Parse(raw)
				if e != nil || u.Hostname() == "" {
					continue
				}
				r.Findings = append(r.Findings, Finding{File: rel, Line: line, Kind: "potential_external_endpoint", Host: u.Hostname(), Confidence: "potential", EvidenceDigest: locationDigest(rel, line, "potential_external_endpoint"), Suggestion: "Declare an approved internal route or disable the optional caller, then exercise the affected workflow."})
			}
			if packageDownload.MatchString(text) {
				r.Findings = append(r.Findings, Finding{File: rel, Line: line, Kind: "potential_runtime_acquisition", Confidence: "potential", EvidenceDigest: locationDigest(rel, line, "potential_runtime_acquisition"), Suggestion: "Stage required artifacts and exact helper images in the release; test from the declared clean offline profile."})
			}
			if strings.Contains(text, "network_mode: host") || strings.Contains(text, "hostNetwork: true") {
				r.Findings = append(r.Findings, Finding{File: rel, Line: line, Kind: "host_network_configuration", Confidence: "configuration", EvidenceDigest: locationDigest(rel, line, "host_network_configuration"), Suggestion: "Review the actual network boundary; this setting alone does not establish isolation."})
			}
		}
		return scanner.Err()
	})
	return r, e
}

// The fingerprint identifies the finding's location and rule, never secret-bearing source bytes.
func locationDigest(file string, line int, rule string) string {
	return spec.Hash([]byte(fmt.Sprintf("%s:%d:%s", file, line, rule)))
}
