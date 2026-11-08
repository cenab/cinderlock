package catalog

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"

	"github.com/cenab/cinderlock/internal/spec"
)

type FileConfig struct {
	APIVersion        string             `json:"apiVersion"`
	Kind              string             `json:"kind"`
	Origin            string             `json:"origin"`
	Actors            []Actor            `json:"actors"`
	PacketKeys        []PacketKey        `json:"packetKeys"`
	OIDC              *OIDCConfig        `json:"oidc,omitempty"`
	NotificationRules []NotificationRule `json:"notificationRules,omitempty"`
	EvidenceKeys      []EvidenceKey      `json:"evidenceKeys,omitempty"`
}

func LoadConfig(ctx context.Context, path string, store *Store) (Config, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Config{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return Config{}, errors.New("catalog configuration must be a private regular file (0600)")
	}
	var file FileConfig
	if err = spec.Read(path, &file); err != nil {
		return Config{}, err
	}
	if file.APIVersion != spec.APIVersion || file.Kind != "CatalogConfig" {
		return Config{}, errors.New("unsupported catalog configuration")
	}
	cfg := Config{Store: store, Actors: file.Actors, PacketKeys: file.PacketKeys, Origin: file.Origin, NotificationRules: file.NotificationRules, EvidenceKeys: file.EvidenceKeys}
	if file.OIDC != nil {
		cfg.OIDC, err = NewOIDC(ctx, *file.OIDC)
		if err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

func GenerateToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	return token, TokenHash(token), nil
}
