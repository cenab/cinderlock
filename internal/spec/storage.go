package spec

type StorageBudget struct {
	Domain          string `json:"domain" yaml:"domain"`
	AdditionalBytes int64  `json:"additionalBytes" yaml:"additionalBytes"`
	TemporaryBytes  int64  `json:"temporaryBytes" yaml:"temporaryBytes"`
}

type StorageCapacity struct {
	Domain         string `json:"domain" yaml:"domain"`
	Binding        string `json:"binding" yaml:"binding"`
	Source         string `json:"source" yaml:"source"`
	AvailableBytes *int64 `json:"availableBytes,omitempty" yaml:"availableBytes,omitempty"`
	RetainedBytes  *int64 `json:"retainedBytes,omitempty" yaml:"retainedBytes,omitempty"`
	ObservedAt     string `json:"observedAt,omitempty" yaml:"observedAt,omitempty"`
	Status         string `json:"status" yaml:"status"`
}

type StorageInventory struct {
	BundleBytes           int64 `json:"bundleBytes" yaml:"bundleBytes"`
	VerifiedPayloadBytes  int64 `json:"verifiedPayloadBytes" yaml:"verifiedPayloadBytes"`
	ImageCompressedBytes  int64 `json:"imageCompressedBytes" yaml:"imageCompressedBytes"`
	ModelBytes            int64 `json:"modelBytes" yaml:"modelBytes"`
	LargestModelFileBytes int64 `json:"largestModelFileBytes" yaml:"largestModelFileBytes"`
}

type StorageDomainPlan struct {
	Domain          string `json:"domain" yaml:"domain"`
	Binding         string `json:"binding" yaml:"binding"`
	Required        bool   `json:"required" yaml:"required"`
	AdditionalBytes int64  `json:"additionalBytes" yaml:"additionalBytes"`
	TemporaryBytes  int64  `json:"temporaryBytes" yaml:"temporaryBytes"`
	RetainedBytes   int64  `json:"retainedBytes" yaml:"retainedBytes"`
	PeakBytes       int64  `json:"peakBytes" yaml:"peakBytes"`
	AvailableBytes  *int64 `json:"availableBytes,omitempty" yaml:"availableBytes,omitempty"`
	Source          string `json:"source" yaml:"source"`
	Confidence      string `json:"confidence" yaml:"confidence"`
}

type StorageBindingPlan struct {
	Binding                 string `json:"binding" yaml:"binding"`
	RequiredAdditionalBytes int64  `json:"requiredAdditionalBytes" yaml:"requiredAdditionalBytes"`
	AvailableBytes          *int64 `json:"availableBytes,omitempty" yaml:"availableBytes,omitempty"`
	Source                  string `json:"source" yaml:"source"`
	Confidence              string `json:"confidence" yaml:"confidence"`
}

type StorageAssessment struct {
	Profile            string               `json:"profile" yaml:"profile"`
	RequirementsDigest string               `json:"requirementsDigest" yaml:"requirementsDigest"`
	Inputs             StorageInventory     `json:"inputs" yaml:"inputs"`
	Domains            []StorageDomainPlan  `json:"domains" yaml:"domains"`
	Bindings           []StorageBindingPlan `json:"bindings" yaml:"bindings"`
	Findings           []Finding            `json:"findings" yaml:"findings"`
	Executable         bool                 `json:"executable" yaml:"executable"`
}
