package catalog

import (
	"errors"
	"net/netip"
	"strings"
	"time"
)

// RuntimeCapture retains a producer's bounded observations, not a verdict about
// functional dependence or independence. Other protocol coverage stays unknown.
type RuntimeCapture struct {
	SchemaVersion        int                  `json:"schemaVersion"`
	StartedAt            string               `json:"startedAt"`
	FinishedAt           string               `json:"finishedAt"`
	ObservedProtocols    []string             `json:"observedProtocols"`
	UnsupportedProtocols []string             `json:"unsupportedProtocols"`
	DroppedEvents        *int64               `json:"droppedEvents"`
	DropUnknownReason    string               `json:"dropUnknownReason,omitempty"`
	Observations         []RuntimeObservation `json:"observations"`
}

type RuntimeObservation struct {
	ID                 string             `json:"id"`
	ObservedAt         string             `json:"observedAt"`
	Protocol           string             `json:"protocol"`
	Source             RuntimeSource      `json:"source"`
	Destination        RuntimeDestination `json:"destination"`
	Outcome            string             `json:"outcome"`
	ProducerConfidence string             `json:"producerConfidence"`
}

type RuntimeSource struct {
	Namespace     string `json:"namespace,omitempty"`
	Container     string `json:"container,omitempty"`
	Process       string `json:"process,omitempty"`
	UnknownReason string `json:"unknownReason,omitempty"`
}

type RuntimeDestination struct {
	Address       string `json:"address,omitempty"`
	Name          string `json:"name,omitempty"`
	Port          *int   `json:"port,omitempty"`
	UnknownReason string `json:"unknownReason,omitempty"`
}

func validRuntimeReason(missing bool, reason string) bool {
	if missing {
		return contains([]string{"not_collected", "not_available", "permission_denied", "unsupported"}, reason)
	}
	return reason == ""
}

func runtimeDNSName(name string) bool {
	if name == "." {
		return true
	}
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func validateRuntimeCapture(capture RuntimeCapture, scope string, observed time.Time) error {
	if scope != "network-isolation" || capture.SchemaVersion != 1 || len(capture.ObservedProtocols) == 0 || len(capture.ObservedProtocols) > 3 || len(capture.UnsupportedProtocols) > 3 || capture.Observations == nil || len(capture.Observations) > 128 {
		return errors.New("runtime capture needs a supported network scope, version, protocols, and bounded explicit observations")
	}
	start, err := time.Parse(time.RFC3339Nano, capture.StartedAt)
	if err != nil {
		return errors.New("runtime capture start time is invalid")
	}
	end, err := time.Parse(time.RFC3339Nano, capture.FinishedAt)
	if err != nil || !end.After(start) || end.After(observed) {
		return errors.New("runtime capture window must be positive and finish by the evidence observation time")
	}
	protocols := map[string]bool{}
	for _, values := range [][]string{capture.ObservedProtocols, capture.UnsupportedProtocols} {
		for _, protocol := range values {
			if !contains([]string{"dns", "tcp", "udp"}, protocol) || protocols[protocol] {
				return errors.New("runtime capture protocol scope is unsupported or duplicated")
			}
			protocols[protocol] = true
		}
	}
	if len(protocols) != 3 || !validRuntimeReason(capture.DroppedEvents == nil, capture.DropUnknownReason) || capture.DroppedEvents != nil && *capture.DroppedEvents < 0 {
		return errors.New("runtime capture must declare protocol gaps and known or explicitly unknown event loss")
	}
	seen := map[string]bool{}
	for _, event := range capture.Observations {
		if !identifier.MatchString(event.ID) || seen[event.ID] || !contains(capture.ObservedProtocols, event.Protocol) || !contains([]string{"low", "medium", "high", "unknown"}, event.ProducerConfidence) {
			return errors.New("runtime observation needs a unique ID, declared protocol, and producer confidence")
		}
		seen[event.ID] = true
		at, err := time.Parse(time.RFC3339Nano, event.ObservedAt)
		if err != nil || at.Before(start) || at.After(end) {
			return errors.New("runtime observation time is outside the capture window")
		}
		source := event.Source
		for _, value := range []string{source.Namespace, source.Container, source.Process} {
			if value != "" && !identifier.MatchString(value) {
				return errors.New("runtime attribution accepts bounded names, never command arguments or raw logs")
			}
		}
		if !validRuntimeReason(source.Namespace == "" || source.Container == "" || source.Process == "", source.UnknownReason) {
			return errors.New("missing runtime source attribution needs an explicit unknown reason")
		}
		destination := event.Destination
		if destination.Address != "" {
			address, err := netip.ParseAddr(destination.Address)
			if err != nil || address.Zone() != "" {
				return errors.New("runtime destination address must be an IP literal without a zone")
			}
		}
		if destination.Name != "" && !runtimeDNSName(destination.Name) || destination.Port != nil && (*destination.Port < 1 || *destination.Port > 65535) {
			return errors.New("runtime destination name or port is invalid")
		}
		missing := destination.Address == "" && destination.Name == "" || destination.Port == nil || event.Protocol == "dns" && destination.Name == ""
		if !validRuntimeReason(missing, destination.UnknownReason) {
			return errors.New("unknown runtime destination details need an explicit reason")
		}
		if !contains([]string{"attempted", "blocked", "failed", "unknown"}, event.Outcome) && !(event.Protocol == "tcp" && event.Outcome == "connected" || event.Protocol == "dns" && event.Outcome == "resolved" || event.Protocol == "udp" && event.Outcome == "sent") {
			return errors.New("runtime observation outcome is unsupported for its protocol")
		}
	}
	return nil
}
