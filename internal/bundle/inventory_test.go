package bundle

import (
	"encoding/json"
	"testing"
)

func TestCycloneDXInventoryIsExplicitAboutCoverage(t *testing.T) {
	f := newFixture(t)
	f.lock.Assets[0].License = "Example vendor model terms"
	bom, err := Inventory(f.lock)
	if err != nil {
		t.Fatal(err)
	}
	if bom.Format != "CycloneDX" || bom.SpecVersion != "1.6" || len(bom.Components) != len(f.lock.Assets) || bom.Compositions[0].Aggregate != "incomplete" {
		t.Fatal("inventory scope incorrect")
	}
	if bom.Components[0].Type != "machine-learning-model" || len(bom.Components[0].Components) != len(f.lock.Assets[0].Files) || bom.Components[0].Licenses[0].License.Name != "Example vendor model terms" {
		t.Fatal("model/files/license declaration missing")
	}
	flags := map[string]string{}
	for _, p := range bom.Properties {
		flags[p.Name] = p.Value
	}
	if flags["cinderlock:packageScanner"] != "not_run" || flags["cinderlock:vulnerabilityScanner"] != "not_run" {
		t.Fatal("inventory misrepresented as scanner result")
	}
	b, err := json.Marshal(bom)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}
	if _, present := obj["vulnerabilities"]; present {
		t.Fatal("unperformed vulnerability scan emitted results")
	}
}
