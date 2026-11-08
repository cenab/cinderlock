package discover

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

type Proposal struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	RuleID string `json:"ruleId"`
	Patch  string `json:"patch"`
}

type ProposalReport struct {
	APIVersion  string     `json:"apiVersion"`
	Kind        string     `json:"kind"`
	Files       int        `json:"files"`
	Proposals   []Proposal `json:"proposals"`
	Coverage    []string   `json:"coverage"`
	Limitations []string   `json:"limitations"`
}

var dotenvAssignment = regexp.MustCompile(`^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)$`)
var proposalPath = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// Propose returns reviewable patches without changing source files.
func Propose(ctx context.Context, root string) (ProposalReport, error) {
	r := ProposalReport{
		APIVersion: spec.APIVersion, Kind: "DiscoveryProposalReport", Proposals: []Proposal{},
		Coverage: []string{
			"Explicit disabled Hugging Face switches only: HF_HUB_OFFLINE, HF_HUB_DISABLE_TELEMETRY, HF_HUB_DISABLE_UPDATE_CHECK",
			"Single-line assignments in .env, .env.*, and *.env; block Compose services environment mappings and lists in .yaml and .yml",
			"Zero-context patches contain only complete allowlisted assignment lines; no source-content hashes",
		},
		Limitations: []string{
			"Proposals require review, preloaded artifacts, and workflow tests; missing cached artifacts can still fail offline",
			"Static configuration proposals do not establish functional dependence, runtime behavior, or isolation",
			"Only literal 0, false, no, and off (case-insensitive, optionally quoted) are changed to 1; absent or enabled switches are skipped",
			"Comments on changed lines, interpolation, multiline or flow constructs, unknown keys, and unsupported layouts are skipped; unsupported dotenv syntax skips the entire file",
			"Hidden directories, vendor, and node_modules are excluded; symlinks, unsafe paths, ambiguous YAML, and duplicate switch assignments are rejected",
			"Only LF and CRLF source line endings are supported; YAML nesting is limited to 64 levels",
			"At most 10000 visited files, 1 MiB per file, 64 MiB total, 100 patches, and 1 MiB of patch text; any error discards all proposals",
			"Sources must remain stable during review; patches do not bind or hash the surrounding file",
		},
	}
	err := ctx.Err()
	if err != nil {
		return r, err
	}
	for _, part := range strings.Split(filepath.ToSlash(root), "/") {
		if part == ".." {
			return r, errors.New("proposal root contains a path escape")
		}
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return r, errors.New("invalid proposal root")
	}
	for parent := root; ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return r, errors.New("proposal root must contain only real directories")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	directory, err := os.OpenRoot(root)
	if err != nil {
		return r, errors.New("cannot open proposal root")
	}
	defer directory.Close()
	var total int64
	patchBytes := 0
	err = fs.WalkDir(directory.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return errors.New("cannot traverse proposal sources")
		}
		if entry.IsDir() {
			if name != "." && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor" || entry.Name() == "node_modules") {
				return fs.SkipDir
			}
			return nil
		}
		if !fs.ValidPath(name) || !proposalPath.MatchString(name) || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return errors.New("unsafe proposal source path or file type")
		}
		info, err := entry.Info()
		if err != nil {
			return errors.New("cannot inspect proposal source")
		}
		r.Files++
		total += info.Size()
		if info.Size() > 1<<20 || r.Files > 10000 || total > 64<<20 {
			return errors.New("proposal source limit exceeded")
		}
		dotenv := entry.Name() == ".env" || strings.HasPrefix(entry.Name(), ".env.") || strings.HasSuffix(entry.Name(), ".env")
		ext := strings.ToLower(filepath.Ext(name))
		if !dotenv && ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := readProposalSource(directory, name, info)
		if err != nil {
			return err
		}
		if dotenv && unsupportedLineBreaks(data) {
			return nil
		}
		lines := strings.SplitAfter(string(data), "\n")
		var changes []lineChange
		if dotenv {
			changes, err = dotenvChanges(ctx, lines)
		} else {
			changes, err = composeChanges(ctx, data, lines)
		}
		if err != nil {
			return err
		}
		for _, change := range changes {
			if err := ctx.Err(); err != nil {
				return err
			}
			patch := fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -%d +%d @@\n%s%s", name, name, change.line, change.line,
				patchLine("-", lines[change.line-1]), patchLine("+", change.text))
			patchBytes += len(patch)
			if len(r.Proposals) >= 100 || patchBytes > 1<<20 {
				return errors.New("proposal output limit exceeded")
			}
			r.Proposals = append(r.Proposals, Proposal{File: name, Line: change.line, RuleID: strings.ToLower(change.key), Patch: patch})
		}
		return nil
	})
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		r.Proposals = []Proposal{}
	}
	return r, err
}

func readProposalSource(root *os.Root, name string, expected fs.FileInfo) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open proposal source")
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || !os.SameFile(expected, before) || before.Size() != expected.Size() {
		return nil, errors.New("proposal source changed during inspection")
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, errors.New("cannot read proposal source")
	}
	after, err := f.Stat()
	if err != nil || len(data) > 1<<20 || int64(len(data)) != before.Size() || after.Size() != before.Size() || after.ModTime() != before.ModTime() {
		return nil, errors.New("proposal source changed or exceeds size limit")
	}
	return data, nil
}

type lineChange struct {
	line int
	key  string
	text string
}

func knownSwitch(key string) bool {
	return key == "HF_HUB_OFFLINE" || key == "HF_HUB_DISABLE_TELEMETRY" || key == "HF_HUB_DISABLE_UPDATE_CHECK"
}

func disabled(value string) bool {
	switch strings.ToLower(value) {
	case "0", "false", "no", "off":
		return true
	}
	return false
}

func dotenvChanges(ctx context.Context, lines []string) ([]lineChange, error) {
	var changes []lineChange
	seen := map[string]bool{}
	for i, raw := range lines {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		text := strings.Trim(raw, " \t\r\n")
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		assignment := dotenvAssignment.FindStringSubmatch(text)
		if assignment == nil || !singleLineDotenvValue(assignment[2]) {
			return nil, nil
		}
		key, token := assignment[1], strings.Trim(assignment[2], " \t")
		if !knownSwitch(key) {
			continue
		}
		if seen[key] {
			return nil, errors.New("ambiguous duplicate dotenv switch")
		}
		seen[key] = true
		value := token
		if len(token) >= 2 && (token[0] == '\'' || token[0] == '"') && token[len(token)-1] == token[0] {
			value = token[1 : len(token)-1]
		}
		if disabled(value) {
			at := strings.LastIndex(raw, value)
			changes = append(changes, lineChange{i + 1, key, raw[:at] + "1" + raw[at+len(value):]})
		}
	}
	return changes, nil
}

// Unsupported quoting or continuations can put later physical lines inside a value.
func singleLineDotenvValue(value string) bool {
	value = strings.Trim(value, " \t")
	if value == "" {
		return true
	}
	if value[0] != '\'' && value[0] != '"' {
		text, _, _ := strings.Cut(value, "#")
		return !strings.ContainsAny(text, "'\"\\\r\n$`;|&()<>")
	}
	for i := 1; i < len(value); i++ {
		if value[i] == '\\' && value[0] == '"' {
			i++
		} else if value[0] == '"' && (value[i] == '$' || value[i] == '`') {
			return false
		} else if value[i] == value[0] {
			tail := strings.Trim(value[i+1:], " \t")
			return tail == "" || strings.HasPrefix(tail, "#")
		}
	}
	return false
}

func composeChanges(ctx context.Context, data []byte, lines []string) ([]lineChange, error) {
	var document, extra yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err == io.EOF {
		return nil, nil
	} else if err != nil {
		return nil, errors.New("invalid proposal YAML")
	}
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("proposal YAML must contain exactly one document")
	}
	if err := validateProposalYAML(ctx, &document, 0); err != nil {
		return nil, err
	}
	if unsupportedLineBreaks(data) {
		return nil, nil
	}
	services := yamlMember(document.Content[0], "services")
	if services == nil || services.Kind != yaml.MappingNode || services.Style != 0 {
		return nil, nil
	}
	var changes []lineChange
	for i := 1; i < len(services.Content); i += 2 {
		environment := yamlMember(services.Content[i], "environment")
		if environment == nil || environment.Style != 0 {
			continue
		}
		if environment.Kind == yaml.SequenceNode && slices.ContainsFunc(environment.Content, func(node *yaml.Node) bool { return node.Kind != yaml.ScalarNode }) {
			continue
		}
		seen := map[string]bool{}
		for j, node := range environment.Content {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var key, value, token string
			switch environment.Kind {
			case yaml.MappingNode:
				if j%2 == 0 {
					continue
				}
				keyNode := environment.Content[j-1]
				key, value = keyNode.Value, node.Value
				if keyNode.Style != 0 || keyNode.Line != node.Line {
					continue
				}
			case yaml.SequenceNode:
				key, value, _ = strings.Cut(node.Value, "=")
				if knownSwitch(strings.TrimSpace(key)) {
					if seen[strings.TrimSpace(key)] {
						return nil, errors.New("ambiguous duplicate Compose switch")
					}
					seen[strings.TrimSpace(key)] = true
				}
			default:
				continue
			}
			if !knownSwitch(key) || !disabled(value) || node.Kind != yaml.ScalarNode {
				continue
			}
			switch node.Style {
			case 0:
				token = node.Value
			case yaml.SingleQuotedStyle:
				token = "'" + node.Value + "'"
			case yaml.DoubleQuotedStyle:
				token = "\"" + node.Value + "\""
			default:
				continue
			}
			raw := lines[node.Line-1]
			text := strings.Trim(raw, " \t\r\n")
			if environment.Kind == yaml.MappingNode {
				left, right, ok := strings.Cut(text, ":")
				if !ok || strings.Trim(left, " \t") != key || strings.Trim(right, " \t") != token {
					continue
				}
			} else if len(text) < 2 || text[0] != '-' || (text[1] != ' ' && text[1] != '\t') || strings.Trim(text[1:], " \t") != token {
				continue
			}
			at := strings.LastIndex(raw, value)
			changes = append(changes, lineChange{node.Line, key, raw[:at] + "1" + raw[at+len(value):]})
		}
	}
	return changes, nil
}

func yamlMember(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode || node.Style != 0 {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key && node.Content[i].Style == 0 {
			return node.Content[i+1]
		}
	}
	return nil
}

func validateProposalYAML(ctx context.Context, node *yaml.Node, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > 64 || node.Anchor != "" || node.Kind == yaml.AliasNode || node.Style&yaml.TaggedStyle != 0 {
		return errors.New("ambiguous or unsupported proposal YAML")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
				return errors.New("ambiguous proposal YAML mapping")
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := validateProposalYAML(ctx, child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func patchLine(prefix, text string) string {
	if strings.HasSuffix(text, "\n") {
		return prefix + text
	}
	return prefix + text + "\n\\ No newline at end of file\n"
}

// YAML counts line separators that LF-based unified patches cannot represent.
func unsupportedLineBreaks(data []byte) bool {
	return bytes.ContainsAny(bytes.ReplaceAll(data, []byte("\r\n"), nil), "\r\u0085\u2028\u2029")
}
