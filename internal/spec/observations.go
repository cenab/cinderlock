package spec

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxObservationBytes = 64 << 10

func validateObservationBudget(checks []Check) error {
	// Reserve the other half of the readable result for operations and failure evidence.
	remaining := MaxDocumentBytes / 2
	for _, check := range checks {
		if check.ObservationContract == nil {
			continue
		}
		contract := *check.ObservationContract
		longestInteger := int64(-9007199254740991)
		report := ObservationReport{Version: 1, ContractDigest: "sha256:" + strings.Repeat("f", 64), Profile: contract.Profile, Runtime: strings.Repeat("r", 128), Device: strings.Repeat("d", 128), Mode: strings.Repeat("m", 128), WarmCold: "unknown", Concurrency: 1024}
		for i := 0; i < contract.SampleCount; i++ {
			sample := ObservationSample{Index: i + 1}
			for _, metric := range contract.Metrics {
				sample.Metrics = append(sample.Metrics, MetricValue{Name: metric.Name, Unit: metric.Unit, Value: &longestInteger})
			}
			report.Samples = append(report.Samples, sample)
		}
		declaration, err := json.Marshal(contract)
		if err != nil {
			return err
		}
		body, err := json.Marshal(report)
		if err != nil {
			return err
		}
		// Source identities and check status are retained alongside the full contract and samples.
		remaining -= len(declaration) + min(len(body), MaxObservationBytes) + 8192
		if remaining < 0 {
			return Err(2, "aggregate observation evidence exceeds the readable result budget; reduce or split the declared check profile")
		}
	}
	return nil
}

// ObservationContract defines application-owned assertions, not independent
// instrumentation or a general model-quality assessment.
type ObservationContract struct {
	Version           int              `json:"version" yaml:"version"`
	TestRevision      string           `json:"testRevision" yaml:"testRevision"`
	AssertionRevision string           `json:"assertionRevision" yaml:"assertionRevision"`
	Profile           string           `json:"profile" yaml:"profile"`
	SampleCount       int              `json:"sampleCount" yaml:"sampleCount"`
	Sampling          map[string]int64 `json:"sampling" yaml:"sampling"`
	Nondeterminism    string           `json:"nondeterminism" yaml:"nondeterminism"`
	Limitations       string           `json:"limitations" yaml:"limitations"`
	Metrics           []MetricBound    `json:"metrics" yaml:"metrics"`
}

type MetricBound struct {
	Name      string `json:"name" yaml:"name"`
	Kind      string `json:"kind" yaml:"kind"`
	Unit      string `json:"unit" yaml:"unit"`
	Assertion string `json:"assertion" yaml:"assertion"`
	Min       *int64 `json:"min" yaml:"min"`
	Max       *int64 `json:"max" yaml:"max"`
}

// ObservationReport is the only document the completed acceptance Job emits.
type ObservationReport struct {
	Version        int                 `json:"version"`
	ContractDigest string              `json:"contractDigest"`
	Profile        string              `json:"profile"`
	Runtime        string              `json:"runtime"`
	Device         string              `json:"device"`
	Mode           string              `json:"mode"`
	WarmCold       string              `json:"warmCold"`
	Concurrency    int                 `json:"concurrency"`
	Samples        []ObservationSample `json:"samples"`
}

type ObservationSample struct {
	Index   int           `json:"index"`
	Metrics []MetricValue `json:"metrics"`
}

type MetricValue struct {
	Name  string `json:"name"`
	Unit  string `json:"unit"`
	Value *int64 `json:"value"`
}

type CheckObservations struct {
	Basis    string              `json:"basis"`
	Contract ObservationContract `json:"contract"`
	Source   ObservationSource   `json:"source"`
	Report   *ObservationReport  `json:"report,omitempty"`
}

type ObservationSource struct {
	JobName      string `json:"jobName"`
	JobUID       string `json:"jobUID"`
	RecipeDigest string `json:"recipeDigest"`
	PodName      string `json:"podName"`
	PodUID       string `json:"podUID"`
	OutputDigest string `json:"outputDigest,omitempty"`
}

func ValidateObservationContract(c ObservationContract) error {
	if c.Version != 1 || !identifier.MatchString(c.TestRevision) || !identifier.MatchString(c.AssertionRevision) || !identifier.MatchString(c.Profile) {
		return Err(2, "observation contract needs version 1 and bounded test/assertion revisions and profile")
	}
	if c.SampleCount < 1 || c.SampleCount > 32 || len(c.Metrics) < 3 || len(c.Metrics) > 16 || len(c.Sampling) < 1 || len(c.Sampling) > 16 {
		return Err(2, "observation contract exceeds sample, metric or sampling-setting bounds")
	}
	if !observationText(c.Nondeterminism, 1024) || !observationText(c.Limitations, 1024) {
		return Err(2, "observation contract needs bounded nondeterminism and sample limitations")
	}
	for name, value := range c.Sampling {
		if !identifier.MatchString(name) || !observationInteger(value) {
			return Err(2, "observation sampling settings need bounded names and safe integers")
		}
	}
	names, kinds := map[string]bool{}, map[string]bool{}
	for _, metric := range c.Metrics {
		if !identifier.MatchString(metric.Name) || names[metric.Name] || !observationText(metric.Assertion, 512) || metric.Min == nil || metric.Max == nil || !observationInteger(*metric.Min) || !observationInteger(*metric.Max) || *metric.Min > *metric.Max {
			return Err(2, "observation metrics need distinct names, assertions and explicit safe inclusive bounds")
		}
		names[metric.Name], kinds[metric.Kind] = true, true
		switch metric.Kind {
		case "latency":
			if metric.Unit != "milliseconds" && metric.Unit != "microseconds" {
				return Err(2, "latency observations require fixed time units")
			}
		case "resource":
			if metric.Unit != "bytes" && metric.Unit != "count" {
				return Err(2, "resource observations require bytes or count units")
			}
		case "assertion":
			if metric.Unit != "count" && metric.Unit != "basis_points" && metric.Unit != "parts_per_million" {
				return Err(2, "assertion observations require count or fixed-ratio units")
			}
		default:
			return Err(2, "unsupported observation metric kind")
		}
		if metric.Kind != "assertion" && *metric.Min < 0 {
			return Err(2, "latency and resource bounds cannot be negative")
		}
	}
	if !kinds["assertion"] || !kinds["latency"] || !kinds["resource"] {
		return Err(2, "observations require application assertion, latency and resource bounds")
	}
	return nil
}

var observationMetadata = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:/()+-]{0,127}$`)

func observationText(s string, limit int) bool {
	return len(s) <= limit && strings.TrimSpace(s) != "" && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

func observationInteger(value int64) bool {
	return value >= -9007199254740991 && value <= 9007199254740991
}

// EvaluateObservations checks every sample; a malformed document never supplies
// partial passing evidence. Parser diagnostics deliberately exclude Job output.
func EvaluateObservations(c ObservationContract, output []byte) (*ObservationReport, bool, error) {
	if err := ValidateObservationContract(c); err != nil {
		return nil, false, err
	}
	trim := bytes.TrimSpace(output)
	var report ObservationReport
	if len(output) > MaxObservationBytes || len(trim) == 0 || trim[0] != '{' || Decode(output, &report) != nil {
		return nil, false, Err(2, "invalid bounded observation JSON document")
	}
	digest, err := Digest(c)
	if err != nil || report.Version != c.Version || report.ContractDigest != digest || report.Profile != c.Profile || len(report.Samples) != c.SampleCount {
		return nil, false, Err(2, "observation document differs from declared contract, profile or sample count")
	}
	if !observationMetadata.MatchString(report.Runtime) || !observationMetadata.MatchString(report.Device) || !observationMetadata.MatchString(report.Mode) || (report.WarmCold != "warm" && report.WarmCold != "cold" && report.WarmCold != "mixed" && report.WarmCold != "unknown") || report.Concurrency < 1 || report.Concurrency > 1024 {
		return nil, false, Err(2, "observation document needs bounded runtime, device, mode, warm/cold and concurrency metadata")
	}
	passed := true
	for i, sample := range report.Samples {
		if sample.Index != i+1 || len(sample.Metrics) != len(c.Metrics) {
			return nil, false, Err(2, "observation samples need consecutive indices and every declared metric")
		}
		for j, value := range sample.Metrics {
			bound := c.Metrics[j]
			if value.Name != bound.Name || value.Unit != bound.Unit || value.Value == nil || !observationInteger(*value.Value) {
				return nil, false, Err(2, "observation metrics must match declared order, names, units and safe integer values")
			}
			if *value.Value < *bound.Min || *value.Value > *bound.Max {
				passed = false
			}
		}
	}
	return &report, passed, nil
}
