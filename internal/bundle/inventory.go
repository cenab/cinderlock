package bundle

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/cenab/cinderlock/internal/spec"
)

func InventoryBytes(v *Verified) ([]byte, error) {
	if v.Index.Inventory == nil {
		return nil, spec.Err(10, "bundle has no signed component inventory")
	}
	d := v.Index.Inventory
	if d.Size > MaxMetadataBytes {
		return nil, spec.Err(12, "inventory exceeds metadata limit")
	}
	if err := VerifyBlob(context.Background(), v.Root, d.Digest, d.Size); err != nil {
		return nil, err
	}
	p, _ := BlobPath(v.Root, d.Digest)
	return os.ReadFile(p)
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type BOMHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}
type BOMLicense struct {
	License struct {
		Name string `json:"name"`
	} `json:"license"`
}
type Component struct {
	Type       string       `json:"type"`
	Ref        string       `json:"bom-ref"`
	Name       string       `json:"name"`
	Version    string       `json:"version,omitempty"`
	Hashes     []BOMHash    `json:"hashes,omitempty"`
	Licenses   []BOMLicense `json:"licenses,omitempty"`
	Properties []Property   `json:"properties,omitempty"`
	Components []Component  `json:"components,omitempty"`
}
type BOMDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}
type Composition struct {
	Aggregate  string   `json:"aggregate"`
	Assemblies []string `json:"assemblies"`
}
type BOM struct {
	Format      string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Component Component `json:"component"`
	} `json:"metadata"`
	Components   []Component     `json:"components"`
	Dependencies []BOMDependency `json:"dependencies"`
	Compositions []Composition   `json:"compositions"`
	Properties   []Property      `json:"properties"`
}

// Inventory describes declared release artifacts, not packages inside images or vulnerability scan results.
func Inventory(lock spec.ReleaseLock) (BOM, error) {
	var bom BOM
	if err := spec.ValidateHeader(lock.Header, "ReleaseLock"); err != nil {
		return bom, err
	}
	if err := spec.ValidateRelease(lock.Release); err != nil {
		return bom, err
	}
	identity, err := spec.Digest(lock)
	if err != nil {
		return bom, err
	}
	bom.Format = "CycloneDX"
	bom.SpecVersion = "1.6"
	bom.Version = 1
	appRef := "cinderlock-release:" + identity
	bom.Metadata.Component = Component{Type: "application", Ref: appRef, Name: lock.Release.Metadata.Application, Version: lock.Release.Metadata.Version, Properties: []Property{{Name: "cinderlock:lockDigest", Value: identity}}}
	bom.Properties = []Property{{Name: "cinderlock:inventoryCoverage", Value: "declared release artifacts and their locked files only"}, {Name: "cinderlock:packageScanner", Value: "not_run"}, {Name: "cinderlock:vulnerabilityScanner", Value: "not_run"}, {Name: "cinderlock:licenseEvidence", Value: "vendor-declared; not independently validated"}}
	bom.Compositions = []Composition{{Aggregate: "incomplete", Assemblies: []string{appRef}}}
	dep := BOMDependency{Ref: appRef, DependsOn: []string{}}
	seen := map[string]bool{}
	for _, a := range lock.Assets {
		if a.ID == "" || seen[a.ID] || !ValidDigest(a.Digest) {
			return BOM{}, fmt.Errorf("invalid locked inventory asset %q", a.ID)
		}
		seen[a.ID] = true
		typeName := "data"
		switch a.Type {
		case "image":
			typeName = "container"
		case "model", "model-tree":
			typeName = "machine-learning-model"
		case "file":
			typeName = "file"
		}
		ref := "cinderlock-asset:" + a.ID
		scope := "tree-manifest"
		if a.Type == "image" {
			scope = "oci-manifest"
		} else if len(a.Files) == 1 && a.Digest == a.Files[0].Digest {
			scope = "file-bytes"
		}
		c := Component{Type: typeName, Ref: ref, Name: a.ID, Version: a.Digest, Hashes: []BOMHash{{Algorithm: "SHA-256", Content: strings.TrimPrefix(a.Digest, "sha256:")}}, Properties: []Property{{Name: "cinderlock:origin", Value: a.Source}, {Name: "cinderlock:digestScope", Value: scope}, {Name: "cinderlock:assetType", Value: a.Type}}}
		if a.License != "" {
			l := BOMLicense{}
			l.License.Name = a.License
			c.Licenses = []BOMLicense{l}
		} else {
			c.Properties = append(c.Properties, Property{Name: "cinderlock:licenseEvidence", Value: "not supplied"})
		}
		paths := map[string]bool{}
		for _, f := range a.Files {
			if !safeMember(f.Path) || paths[f.Path] || !ValidDigest(f.Digest) || f.Size < 0 {
				return BOM{}, fmt.Errorf("invalid locked inventory file %q", f.Path)
			}
			paths[f.Path] = true
			c.Components = append(c.Components, Component{Type: "file", Ref: ref + "/file/" + spec.Hash([]byte(f.Path))[7:], Name: f.Path, Hashes: []BOMHash{{Algorithm: "SHA-256", Content: f.Digest[7:]}}})
		}
		bom.Components = append(bom.Components, c)
		dep.DependsOn = append(dep.DependsOn, ref)
	}
	bom.Dependencies = []BOMDependency{dep}
	return bom, nil
}
