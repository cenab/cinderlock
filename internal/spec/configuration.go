package spec

import (
	"regexp"
	"sort"
	"strings"
)

var configurationSegment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)

func ValidConfigurationPath(path string) bool {
	if len(path) == 0 || len(path) > 256 {
		return false
	}
	parts := strings.Split(path, ".")
	if len(parts) > 16 {
		return false
	}
	for _, part := range parts {
		if !configurationSegment.MatchString(part) {
			return false
		}
	}
	return true
}

func ValidateConfigurationContract(deployment Deployment) error {
	contract := deployment.Configuration
	if contract == nil {
		return nil
	}
	if contract.Version != 1 || len(contract.Fields) == 0 || len(contract.Fields) > 256 {
		return Err(2, "configuration contract needs version 1 and 1..256 fields")
	}
	fields := append([]ConfigurationField(nil), contract.Fields...)
	sort.Slice(fields, func(i, j int) bool { return fields[i].Path < fields[j].Path })
	generated := map[string]bool{}
	for _, binding := range deployment.ImageBindings {
		_, exists := generated[binding.ValuesPath]
		if !ValidConfigurationPath(binding.ValuesPath) || exists {
			return Err(2, "configuration image bindings need distinct explicit dotted paths")
		}
		generated[binding.ValuesPath] = false
	}
	for i, field := range fields {
		if !ValidConfigurationPath(field.Path) {
			return Err(2, "configuration field needs a bounded explicit dotted path")
		}
		for _, prior := range fields[:i] {
			if prior.Path == field.Path || strings.HasPrefix(field.Path, prior.Path+".") {
				return Err(2, "configuration ownership paths cannot overlap")
			}
		}
		switch field.Type {
		case "string", "boolean", "integer", "array", "object":
		default:
			return Err(2, "configuration field %s has an unsupported type", field.Path)
		}
		switch field.Owner {
		case "vendor", "site":
		case "generated":
			if _, ok := generated[field.Path]; !ok || field.Type != "string" {
				return Err(2, "generated configuration field must be an exact string image binding")
			}
			generated[field.Path] = true
		default:
			return Err(2, "configuration field %s has an unsupported owner", field.Path)
		}
	}
	for _, present := range generated {
		if !present {
			return Err(2, "each image binding needs an exact generated string configuration field")
		}
	}
	return nil
}

// ConfigurationContract governs explicit dotted Helm value paths. Objects and
// arrays are atomic ownership scopes; child rules cannot overlap a parent rule.
type ConfigurationContract struct {
	Version int                  `json:"version" yaml:"version"`
	Fields  []ConfigurationField `json:"fields" yaml:"fields"`
}

type ConfigurationField struct {
	Path     string `json:"path" yaml:"path"`
	Owner    string `json:"owner" yaml:"owner"`
	Type     string `json:"type" yaml:"type"`
	Required bool   `json:"required,omitempty" yaml:"required,omitempty"`
}

// ConfigurationReview deliberately contains no values or unkeyed value hashes.
type ConfigurationReview struct {
	Ownership          string                     `json:"ownership" yaml:"ownership"`
	ComparisonRevision int64                      `json:"comparisonRevision" yaml:"comparisonRevision"`
	ComparisonStatus   string                     `json:"comparisonStatus" yaml:"comparisonStatus"`
	EffectiveDigest    string                     `json:"effectiveDigest,omitempty" yaml:"effectiveDigest,omitempty"`
	Fields             []ConfigurationFieldReview `json:"fields" yaml:"fields"`
}

type ConfigurationFieldReview struct {
	Path   string `json:"path" yaml:"path"`
	Owner  string `json:"owner" yaml:"owner"`
	Change string `json:"change" yaml:"change"`
}
