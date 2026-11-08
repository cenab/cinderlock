package discover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProposalReadDoesNotBlockOnReplacedFIFO(t *testing.T) {
	dir := proposalRoot(t)
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("HF_HUB_OFFLINE=0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readProposalSource(root, ".env", expected); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("replaced input accepted")
		}
	case <-time.After(time.Second):
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		<-done
		t.Fatal("input replacement blocked the reader")
	}
}

func proposalRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestProposeDotenvReviewableAndUnchanged(t *testing.T) {
	root := proposalRoot(t)
	source := "TOKEN=adjacent-secret\nHF_HUB_OFFLINE=0\n  HF_HUB_DISABLE_TELEMETRY = 'false'  \nHF_HUB_DISABLE_UPDATE_CHECK=OFF"
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := Propose(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	want := []Proposal{
		{File: ".env", Line: 2, RuleID: "hf_hub_offline", Patch: "--- a/.env\n+++ b/.env\n@@ -2 +2 @@\n-HF_HUB_OFFLINE=0\n+HF_HUB_OFFLINE=1\n"},
		{File: ".env", Line: 3, RuleID: "hf_hub_disable_telemetry", Patch: "--- a/.env\n+++ b/.env\n@@ -3 +3 @@\n-  HF_HUB_DISABLE_TELEMETRY = 'false'  \n+  HF_HUB_DISABLE_TELEMETRY = '1'  \n"},
		{File: ".env", Line: 4, RuleID: "hf_hub_disable_update_check", Patch: "--- a/.env\n+++ b/.env\n@@ -4 +4 @@\n-HF_HUB_DISABLE_UPDATE_CHECK=OFF\n\\ No newline at end of file\n+HF_HUB_DISABLE_UPDATE_CHECK=1\n\\ No newline at end of file\n"},
	}
	if !reflect.DeepEqual(report.Proposals, want) {
		t.Fatalf("proposals = %#v; want %#v", report.Proposals, want)
	}
	if report.Kind != "DiscoveryProposalReport" || report.APIVersion == "" || report.Files != 1 || len(report.Coverage) == 0 || len(report.Limitations) == 0 {
		t.Fatalf("incomplete report: %#v", report)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != source {
		t.Fatalf("source changed: %q, %v", after, err)
	}
}

func TestProposeComposeMappingAndList(t *testing.T) {
	root := proposalRoot(t)
	source := "services:\r\n  app:\r\n    environment:\r\n      HF_HUB_OFFLINE: \"false\"\r\n      HF_HUB_DISABLE_TELEMETRY: 0\r\n      OTHER: adjacent-secret\r\n  worker:\r\n    environment:\r\n      - HF_HUB_DISABLE_UPDATE_CHECK=NO\r\n      - 'HF_HUB_OFFLINE=0'\r\n      - \"HF_HUB_DISABLE_TELEMETRY=off\""
	path := filepath.Join(root, "compose.yaml")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := Propose(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	want := []Proposal{
		{File: "compose.yaml", Line: 4, RuleID: "hf_hub_offline", Patch: "--- a/compose.yaml\n+++ b/compose.yaml\n@@ -4 +4 @@\n-      HF_HUB_OFFLINE: \"false\"\r\n+      HF_HUB_OFFLINE: \"1\"\r\n"},
		{File: "compose.yaml", Line: 5, RuleID: "hf_hub_disable_telemetry", Patch: "--- a/compose.yaml\n+++ b/compose.yaml\n@@ -5 +5 @@\n-      HF_HUB_DISABLE_TELEMETRY: 0\r\n+      HF_HUB_DISABLE_TELEMETRY: 1\r\n"},
		{File: "compose.yaml", Line: 9, RuleID: "hf_hub_disable_update_check", Patch: "--- a/compose.yaml\n+++ b/compose.yaml\n@@ -9 +9 @@\n-      - HF_HUB_DISABLE_UPDATE_CHECK=NO\r\n+      - HF_HUB_DISABLE_UPDATE_CHECK=1\r\n"},
		{File: "compose.yaml", Line: 10, RuleID: "hf_hub_offline", Patch: "--- a/compose.yaml\n+++ b/compose.yaml\n@@ -10 +10 @@\n-      - 'HF_HUB_OFFLINE=0'\r\n+      - 'HF_HUB_OFFLINE=1'\r\n"},
		{File: "compose.yaml", Line: 11, RuleID: "hf_hub_disable_telemetry", Patch: "--- a/compose.yaml\n+++ b/compose.yaml\n@@ -11 +11 @@\n-      - \"HF_HUB_DISABLE_TELEMETRY=off\"\n\\ No newline at end of file\n+      - \"HF_HUB_DISABLE_TELEMETRY=1\"\n\\ No newline at end of file\n"},
	}
	if !reflect.DeepEqual(report.Proposals, want) {
		t.Fatalf("proposals = %#v; want %#v", report.Proposals, want)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != source {
		t.Fatalf("source changed: %q, %v", after, err)
	}
}

func TestProposeSkipsUnsupportedSyntax(t *testing.T) {
	cases := []struct {
		name, file, source string
	}{
		{"dotenv absent", ".env", "TOKEN=secret\n"},
		{"dotenv enabled or unknown", ".env", "HF_HUB_OFFLINE=1\nHF_HUB_DISABLE_TELEMETRY=true\nHF_HUB_DISABLE_UPDATE_CHECK=yes\nUNKNOWN=0\n"},
		{"dotenv empty or arbitrary", ".env", "HF_HUB_OFFLINE=\nHF_HUB_DISABLE_TELEMETRY=secret\nHF_HUB_DISABLE_UPDATE_CHECK=2\n"},
		{"dotenv comments", ".env", "# HF_HUB_OFFLINE=0 secret\nHF_HUB_OFFLINE=0 # secret\nHF_HUB_DISABLE_TELEMETRY='false' # secret\n"},
		{"dotenv interpolation", ".env", "HF_HUB_OFFLINE=${VALUE:-0}\nHF_HUB_DISABLE_TELEMETRY=\"${VALUE:-false}\"\n"},
		{"dotenv export", ".env", "export HF_HUB_OFFLINE=0\n"},
		{"dotenv multiline", ".env", "TOKEN=\"start\nHF_HUB_OFFLINE=0\nend\"\nHF_HUB_DISABLE_TELEMETRY=0\n"},
		{"dotenv single quote multiline", ".env", "TOKEN='start\nHF_HUB_OFFLINE=0\nend'\n"},
		{"dotenv continuation", ".env", "TOKEN=value\\\nHF_HUB_OFFLINE=0\n"},
		{"dotenv backtick multiline", ".env", "TOKEN=`\nHF_HUB_OFFLINE=0\nEND=`\n"},
		{"dotenv command multiline", ".env", "TOKEN=$(\nHF_HUB_OFFLINE=0\nEND=)\n"},
		{"dotenv parameter multiline", ".env", "TOKEN=${OTHER:-\nHF_HUB_OFFLINE=0\nEND=}\n"},
		{"dotenv quoted command multiline", ".env", "TOKEN=\"$(printf \"\nHF_HUB_OFFLINE=0\nEND=\")\"\n"},
		{"dotenv heredoc", ".env", "TOKEN= <<END=EOF\nHF_HUB_OFFLINE=0\nEND=EOF\n"},
		{"dotenv shell grouping", ".env", "TOKEN=value; (\nHF_HUB_OFFLINE=0\nEND=)\n"},
		{"dotenv unknown syntax", ".env", "HF_HUB_OFFLINE=0\n$(command)\n"},
		{"dotenv lookalike", ".env", "HF_HUB_OFFLINE_EXTRA=0\nhf_hub_offline=0\nHF_HUB_DISABLE_TELEMETRY=false-secret\n"},
		{"unsupported filename", "settings.txt", "HF_HUB_OFFLINE=0\n"},
		{"yaml outside services", "app.yml", "environment:\n  HF_HUB_OFFLINE: 0\n"},
		{"yaml unknown keys", "compose.yml", "services:\n  app:\n    environment:\n      UNKNOWN: 0\n      HF_HUB_OFFLINE_EXTRA: 0\n"},
		{"yaml comment", "compose.yml", "services:\n  app:\n    environment:\n      HF_HUB_OFFLINE: 0 # secret\n      -INVALID: false\n"},
		{"yaml list comment", "compose.yml", "services:\n  app:\n    environment:\n      - HF_HUB_OFFLINE=0 # secret\n"},
		{"yaml interpolation", "compose.yml", "services:\n  app:\n    environment:\n      HF_HUB_OFFLINE: ${VALUE:-0}\n"},
		{"yaml block scalar", "compose.yml", "services:\n  app:\n    environment:\n      HF_HUB_OFFLINE: |-\n        0\n"},
		{"yaml multiline quoted scalar", "compose.yml", "services:\n  app:\n    environment:\n      HF_HUB_OFFLINE: \"\n        false\"\n"},
		{"yaml folded list scalar", "compose.yml", "services:\n  app:\n    environment:\n      - >-\n        HF_HUB_OFFLINE=0\n"},
		{"yaml flow root", "compose.yml", "{services: {app: {environment: {HF_HUB_OFFLINE: 0}}}}\n"},
		{"yaml flow environment", "compose.yml", "services:\n  app:\n    environment: {HF_HUB_OFFLINE: 0}\n"},
		{"yaml flow ancestor", "compose.yml", "services:\n  app: {environment: {HF_HUB_OFFLINE: 0}}\n"},
		{"yaml quoted key", "compose.yml", "services:\n  app:\n    environment:\n      'HF_HUB_OFFLINE': 0\n"},
		{"yaml explicit key", "compose.yml", "services:\n  app:\n    environment:\n      ? HF_HUB_OFFLINE\n      : 0\n"},
		{"yaml value on next line", "compose.yml", "services:\n  app:\n    environment:\n      HF_HUB_OFFLINE:\n        0\n"},
		{"yaml escaped literal", "compose.yml", "services:\n  app:\n    environment:\n      HF_HUB_OFFLINE: \"o\\x66f\"\n"},
		{"yaml non-scalar list entry", "compose.yml", "services:\n  app:\n    environment:\n      - HF_HUB_OFFLINE=0\n      - UNKNOWN: secret\n"},
		{"yaml bare carriage returns", "compose.yml", "services:\r  app:\r    environment:\r      HF_HUB_OFFLINE: 0\r"},
		{"yaml mixed carriage returns", "compose.yml", "services:\n  app:\r    environment:\n      HF_HUB_OFFLINE: 0\n"},
		{"yaml Unicode line breaks", "compose.yml", "services:\u0085  app:\u2028    environment:\u2029      HF_HUB_OFFLINE: 0\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := proposalRoot(t)
			path := filepath.Join(root, tc.file)
			if err := os.WriteFile(path, []byte(tc.source), 0600); err != nil {
				t.Fatal(err)
			}
			report, err := Propose(context.Background(), root)
			if err != nil || len(report.Proposals) != 0 {
				t.Fatalf("unsupported input produced proposals or error: %#v, %v", report.Proposals, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != tc.source {
				t.Fatalf("source changed: %q, %v", after, err)
			}
		})
	}
}

func TestProposeRejectsAmbiguousSyntaxWithoutPartialPatches(t *testing.T) {
	cases := []struct{ file, source string }{
		{"z.env", "HF_HUB_OFFLINE=0\nHF_HUB_OFFLINE=1\n"},
		{"z.env", "HF_HUB_OFFLINE=0\nHF_HUB_OFFLINE=secret # comment\n"},
		{"z.yml", "services: [malformed-secret\n"},
		{"z.yml", "services:\n  app:\n    environment:\n      HF_HUB_OFFLINE: 0\n      HF_HUB_OFFLINE: 1\n"},
		{"z.yml", "services: {}\nservices: {}\n"},
		{"z.yml", "services: {}\nother: {secret: 0, secret: 1}\n"},
		{"z.yml", "services: &services {}\n"},
		{"z.yml", "services: &services {}\r"},
		{"z.yml", "other: &base {}\nservices: *base\n"},
		{"z.yml", "services: {}\nother:\n  <<: {secret: value}\n"},
		{"z.yml", "services: {}\n? [complex, secret]\n: value\n"},
		{"z.yml", "services: !custom {}\n"},
		{"z.yml", "services:\n  app:\n    environment:\n      HF_HUB_OFFLINE: !!str 0\n"},
		{"z.yml", "services: {}\n---\nservices: {}\n"},
		{"z.yml", "other: " + strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65) + "\n"},
		{"z.yml", "services:\n  app:\n    environment:\n      - HF_HUB_OFFLINE=0\n      - HF_HUB_OFFLINE=secret # comment\n"},
	}
	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			root := proposalRoot(t)
			for name, source := range map[string]string{"a.env": "HF_HUB_OFFLINE=0\n", tc.file: tc.source} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			report, err := Propose(context.Background(), root)
			if err == nil || len(report.Proposals) != 0 {
				t.Fatalf("ambiguous input was not rejected atomically: %#v, %v", report.Proposals, err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), root) {
				t.Fatalf("error exposes source or absolute path: %v", err)
			}
		})
	}
}

func TestProposePrivacyIndependentOfUnrelatedSecrets(t *testing.T) {
	root := proposalRoot(t)
	write := func(secret string) []byte {
		t.Helper()
		sources := map[string]string{
			".env":         "TOKEN=\"https://user:" + secret + "@example.test/?token=" + secret + "\"\nHF_HUB_OFFLINE=0\nHF_HUB_DISABLE_TELEMETRY=0 # " + secret + "\n# " + secret + "\nHF_HUB_DISABLE_UPDATE_CHECK=" + secret + "\n",
			"compose.yaml": "services:\n  app:\n    environment:\n      TOKEN: '" + secret + "'\n      HF_HUB_OFFLINE: false\n      HF_HUB_DISABLE_TELEMETRY: 0 # " + secret + "\n      # " + secret + "\n      HF_HUB_DISABLE_UPDATE_CHECK: '" + secret + "'\n",
		}
		for name, source := range sources {
			if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
		}
		report, err := Propose(context.Background(), root)
		if err != nil || len(report.Proposals) != 2 {
			t.Fatalf("privacy fixture: %#v, %v", report.Proposals, err)
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{secret, "https://", "example.test", "TOKEN", "sha256", "digest", "hash\""} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("report contains private or derived content %q: %s", forbidden, encoded)
			}
		}
		return encoded
	}
	first := write("first-secret")
	second := write("different-longer-secret")
	if string(first) != string(second) {
		t.Fatalf("report depends on adjacent, commented, or arbitrary values:\n%s\n%s", first, second)
	}
	var rejected string
	for _, secret := range []string{"invalid-secret", "another-invalid-secret"} {
		if err := os.WriteFile(filepath.Join(root, "z.yml"), []byte("services: {\""+secret+"\": [invalid}"), 0600); err != nil {
			t.Fatal(err)
		}
		report, err := Propose(context.Background(), root)
		encoded, marshalErr := json.Marshal(report)
		if err == nil || marshalErr != nil || len(report.Proposals) != 0 || strings.Contains(string(encoded)+err.Error(), secret) {
			t.Fatalf("malformed YAML leaks source or partial patches: %s, %v, %v", encoded, err, marshalErr)
		}
		result := string(encoded) + err.Error()
		if rejected != "" && rejected != result {
			t.Fatal("refusal report or error depends on secret-bearing YAML")
		}
		rejected = result
	}
}

func TestProposeCancellationAndPaths(t *testing.T) {
	root := proposalRoot(t)
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("HF_HUB_OFFLINE=0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for _, ctx := range []context.Context{canceled, expired} {
		report, err := Propose(ctx, root)
		if !errors.Is(err, ctx.Err()) || len(report.Proposals) != 0 {
			t.Fatalf("cancellation not honored: %#v, %v", report.Proposals, err)
		}
	}
	for _, path := range []string{filepath.Join(root, ".env"), filepath.Join(root, "missing"), root + "/child/../"} {
		report, err := Propose(context.Background(), path)
		if err == nil || len(report.Proposals) != 0 {
			t.Fatalf("invalid root accepted: %q, %#v, %v", path, report.Proposals, err)
		}
	}
	for _, name := range []string{"escape.env", "directory", "bad\nheader.env", "bad\theader.env", "bad\\header.env"} {
		t.Run(name, func(t *testing.T) {
			isolated := proposalRoot(t)
			if name == "escape.env" || name == "directory" {
				target := filepath.Join(root, ".env")
				if name == "directory" {
					target = root
				}
				if err := os.Symlink(target, filepath.Join(isolated, name)); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(isolated, name), []byte("HF_HUB_OFFLINE=0\n"), 0600); err != nil {
				t.Fatal(err)
			}
			report, err := Propose(context.Background(), isolated)
			if err == nil || len(report.Proposals) != 0 {
				t.Fatalf("unsafe source accepted: %#v, %v", report.Proposals, err)
			}
		})
	}
	link := filepath.Join(proposalRoot(t), "root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, link + "/."} {
		if report, err := Propose(context.Background(), path); err == nil || len(report.Proposals) != 0 {
			t.Fatalf("symlink root accepted: %#v, %v", report.Proposals, err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if report, err := Propose(context.Background(), filepath.Join(link, "nested")); err == nil || len(report.Proposals) != 0 {
		t.Fatalf("symlink ancestor accepted: %#v, %v", report.Proposals, err)
	}
}

func TestProposeExclusionsAndFileRelativePaths(t *testing.T) {
	root := proposalRoot(t)
	for _, dir := range []string{".git", ".private", "vendor", "node_modules", "config"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
		source := "HF_HUB_OFFLINE=0\n"
		if dir != "config" {
			source += strings.Repeat("x", 1<<20)
		}
		if err := os.WriteFile(filepath.Join(root, dir, ".env.production"), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "dev.env"), []byte("HF_HUB_DISABLE_TELEMETRY=No\n"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := Propose(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	want := []Proposal{
		{File: "config/.env.production", Line: 1, RuleID: "hf_hub_offline", Patch: "--- a/config/.env.production\n+++ b/config/.env.production\n@@ -1 +1 @@\n-HF_HUB_OFFLINE=0\n+HF_HUB_OFFLINE=1\n"},
		{File: "dev.env", Line: 1, RuleID: "hf_hub_disable_telemetry", Patch: "--- a/dev.env\n+++ b/dev.env\n@@ -1 +1 @@\n-HF_HUB_DISABLE_TELEMETRY=No\n+HF_HUB_DISABLE_TELEMETRY=1\n"},
	}
	if report.Files != 2 || !reflect.DeepEqual(report.Proposals, want) {
		t.Fatalf("exclusions or relative paths differ: %#v; want %#v", report, want)
	}
}

func TestProposeSourceAndOutputLimits(t *testing.T) {
	t.Run("file bytes", func(t *testing.T) {
		root := proposalRoot(t)
		path := filepath.Join(root, ".env")
		prefix := "HF_HUB_OFFLINE=0\n#"
		atLimit := prefix + strings.Repeat("x", (1<<20)-len(prefix))
		if err := os.WriteFile(path, []byte(atLimit), 0600); err != nil {
			t.Fatal(err)
		}
		if report, err := Propose(context.Background(), root); err != nil || len(report.Proposals) != 1 {
			t.Fatalf("exact file limit rejected: %#v, %v", report.Proposals, err)
		}
		if err := os.WriteFile(path, []byte(atLimit+"x"), 0600); err != nil {
			t.Fatal(err)
		}
		if report, err := Propose(context.Background(), root); err == nil || len(report.Proposals) != 0 {
			t.Fatalf("oversized file accepted: %#v, %v", report.Proposals, err)
		}
	})
	t.Run("total bytes", func(t *testing.T) {
		root := proposalRoot(t)
		data := []byte(strings.Repeat("x", 1<<20))
		for i := range 64 {
			if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%02d.txt", i)), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if report, err := Propose(context.Background(), root); err != nil || report.Files != 64 || len(report.Proposals) != 0 {
			t.Fatalf("exact total byte limit rejected: %#v, %v", report, err)
		}
		if err := os.WriteFile(filepath.Join(root, "overflow.txt"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if report, err := Propose(context.Background(), root); err == nil || len(report.Proposals) != 0 {
			t.Fatalf("total byte limit not enforced: %#v, %v", report.Proposals, err)
		}
	})
	t.Run("file count", func(t *testing.T) {
		root := proposalRoot(t)
		for i := range 10000 {
			if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%05d.txt", i)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if report, err := Propose(context.Background(), root); err != nil || report.Files != 10000 || len(report.Proposals) != 0 {
			t.Fatalf("exact file count limit rejected: %#v, %v", report, err)
		}
		if err := os.WriteFile(filepath.Join(root, "overflow.txt"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if report, err := Propose(context.Background(), root); err == nil || len(report.Proposals) != 0 {
			t.Fatalf("file count limit not enforced: %#v, %v", report.Proposals, err)
		}
	})
	t.Run("patch count", func(t *testing.T) {
		root := proposalRoot(t)
		for i := range 100 {
			if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%03d.env", i)), []byte("HF_HUB_OFFLINE=0\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if report, err := Propose(context.Background(), root); err != nil || len(report.Proposals) != 100 || report.Proposals[99].File != "099.env" {
			t.Fatalf("exact patch count limit rejected: %#v, %v", report.Proposals, err)
		}
		if err := os.WriteFile(filepath.Join(root, "overflow.env"), []byte("HF_HUB_OFFLINE=0\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if report, err := Propose(context.Background(), root); err == nil || len(report.Proposals) != 0 {
			t.Fatalf("patch count limit not enforced: %#v, %v", report.Proposals, err)
		}
	})
	t.Run("patch bytes", func(t *testing.T) {
		root := proposalRoot(t)
		source := strings.Repeat(" ", 600<<10) + "HF_HUB_OFFLINE=0\n"
		if err := os.WriteFile(filepath.Join(root, ".env"), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		if report, err := Propose(context.Background(), root); err == nil || len(report.Proposals) != 0 {
			t.Fatalf("patch byte limit not enforced: %#v, %v", report.Proposals, err)
		}
	})
}
