package discover

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanDoesNotExposeSourceSecrets(t *testing.T) {
	d := t.TempDir()
	secret := "secret-test-token"
	if e := os.WriteFile(filepath.Join(d, "app.py"), []byte("url='https://user:"+secret+"@models.example/a?token="+secret+"'\nfrom_pretrained('x')"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := Scan(context.Background(), d)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Findings) != 2 {
		t.Fatal(r)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), secret) {
		t.Fatal("secret leaked")
	}
	if r.Findings[0].Host != "models.example" {
		t.Fatal(r)
	}
}

func TestFindingIdentityDoesNotHashSecretMaterial(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "app.py")
	write := func(secret string) Report {
		t.Helper()
		if e := os.WriteFile(p, []byte("url='https://u:"+secret+"@models.example/a?token="+secret+"'"), 0600); e != nil {
			t.Fatal(e)
		}
		r, e := Scan(context.Background(), d)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	a, b := write("password-one"), write("password-two")
	if a.Findings[0].EvidenceDigest != b.Findings[0].EvidenceDigest {
		t.Fatal("finding fingerprint depends on a secret value")
	}
}
