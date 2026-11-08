package catalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

const packetDomain = "cinderlock.catalog-packet.v1\x00"
const PacketVersion = "cinderlock.dev/v1alpha1"

type PacketBody struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Issuer     string   `json:"issuer"`
	Project    string   `json:"project"`
	Site       string   `json:"site,omitempty"`
	Sequence   int64    `json:"sequence"`
	CreatedAt  string   `json:"createdAt"`
	Records    []Record `json:"records"`
}

type Packet struct {
	Body      json.RawMessage `json:"body"`
	KeyID     string          `json:"keyID"`
	Signature string          `json:"signature"`
}

type PacketKey struct {
	ID        string   `json:"id"`
	PublicKey string   `json:"publicKey"`
	Projects  []string `json:"projects"`
	Sites     []string `json:"sites"`
	Kinds     []string `json:"kinds,omitempty"`
	Revoked   bool     `json:"revoked,omitempty"`
}

func SignPacket(body PacketBody, keyID string, key ed25519.PrivateKey) (Packet, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Packet{}, errors.New("invalid packet private key")
	}
	if keyID != body.Issuer {
		return Packet{}, errors.New("packet issuer must match signing key ID")
	}
	body.APIVersion = PacketVersion
	body.Kind = "CatalogPacket"
	if body.CreatedAt == "" {
		body.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := validatePacketBody(body); err != nil {
		return Packet{}, err
	}
	b, err := canonical(body)
	if err != nil {
		return Packet{}, err
	}
	if len(b) > MaxObjectBytes {
		return Packet{}, errors.New("packet exceeds size limit")
	}
	return Packet{Body: b, KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(packetDomain), b...)))}, nil
}

func VerifyPacket(p Packet, keys []PacketKey) (PacketBody, string, error) {
	var body PacketBody
	if len(p.Body) > MaxObjectBytes {
		return body, "", errors.New("packet too large")
	}
	b, err := canonical(p.Body)
	if err != nil || !bytes.Equal(b, p.Body) {
		return body, "", errors.New("packet body must be canonical JSON")
	}
	if err = strictJSON(p.Body, &body); err != nil {
		return body, "", err
	}
	if err = validatePacketBody(body); err != nil {
		return body, "", err
	}
	var trusted *PacketKey
	for i := range keys {
		if keys[i].ID == p.KeyID {
			if trusted != nil {
				return body, "", errors.New("duplicate packet key identity")
			}
			trusted = &keys[i]
		}
	}
	if trusted == nil || trusted.Revoked || !slices.Contains(trusted.Projects, body.Project) || (len(trusted.Sites) > 0 && !slices.Contains(trusted.Sites, body.Site)) {
		return body, "", errors.New("packet issuer is not admitted for this scope")
	}
	for _, r := range body.Records {
		if len(trusted.Kinds) > 0 && !slices.Contains(trusted.Kinds, r.Kind) {
			return body, "", errors.New("packet key is not admitted for this record kind")
		}
		if len(trusted.Kinds) == 0 && (r.Kind == "TrustPolicy" || r.Kind == "PolicyPack" || r.Kind == "Approval") {
			return body, "", errors.New("policy and approval observations need an explicit packet-key kind scope")
		}
	}
	key, err := base64.StdEncoding.DecodeString(trusted.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return body, "", errors.New("invalid admitted packet public key")
	}
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil || !ed25519.Verify(key, append([]byte(packetDomain), p.Body...), sig) {
		return body, "", errors.New("invalid packet signature")
	}
	if body.Issuer != p.KeyID {
		return body, "", errors.New("packet issuer must match admitted key identity")
	}
	return body, digestBytes(p.Body), nil
}

func validatePacketBody(b PacketBody) error {
	if b.APIVersion != PacketVersion || b.Kind != "CatalogPacket" {
		return errors.New("unsupported packet format or capability")
	}
	if !identifier.MatchString(b.Issuer) || !identifier.MatchString(b.Project) || (b.Site != "" && !identifier.MatchString(b.Site)) || b.Sequence < 1 {
		return errors.New("invalid packet scope or sequence")
	}
	if len(b.Records) == 0 || len(b.Records) > 128 {
		return errors.New("packet must contain 1 to 128 records")
	}
	if _, err := time.Parse(time.RFC3339Nano, b.CreatedAt); err != nil {
		return errors.New("invalid packet observation time")
	}
	for _, r := range b.Records {
		if r.Project != b.Project || r.Site != b.Site {
			return errors.New("packet crosses declared project/site scope")
		}
		if _, _, _, err := normalizeRecord(r); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Import(ctx context.Context, actor string, p Packet, keys []PacketKey) (string, error) {
	body, digest, err := VerifyPacket(p, keys)
	if err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, s.q(`INSERT INTO catalog_streams(issuer,project,site,sequence,digest) VALUES(?,?,?,0,'') ON CONFLICT DO NOTHING`), body.Issuer, body.Project, body.Site)
	if err != nil {
		return "", err
	}
	var seq int64
	var previous string
	if err = tx.QueryRowContext(ctx, s.q(`SELECT sequence,digest FROM catalog_streams WHERE issuer=? AND project=? AND site=?`), body.Issuer, body.Project, body.Site).Scan(&seq, &previous); err != nil {
		return "", err
	}
	if body.Sequence == seq && digest == previous {
		return digest, nil
	}
	if body.Sequence <= seq {
		return "", fmt.Errorf("%w: packet sequence reused or older than admitted stream", ErrConflict)
	}
	changed, err := tx.ExecContext(ctx, s.q(`UPDATE catalog_streams SET sequence=?,digest=? WHERE issuer=? AND project=? AND site=? AND sequence=? AND digest=?`), body.Sequence, digest, body.Issuer, body.Project, body.Site, seq, previous)
	if err != nil {
		return "", err
	}
	n, err := changed.RowsAffected()
	if err != nil || n != 1 {
		return "", fmt.Errorf("%w: stream changed", ErrConflict)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, r := range body.Records {
		r, b, d, e := normalizeRecord(r)
		if e != nil {
			return "", e
		}
		if _, err = tx.ExecContext(ctx, s.q(`INSERT INTO catalog_records(project,site,kind,digest,body,imported_at) VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING`), r.Project, r.Site, r.Kind, d, b, now); err != nil {
			return "", err
		}
	}
	if _, err = tx.ExecContext(ctx, s.q(`INSERT INTO catalog_imports(digest,actor,imported_at) VALUES(?,?,?) ON CONFLICT DO NOTHING`), digest, actor, now); err != nil {
		return "", err
	}
	if err = s.auditTx(ctx, tx, actor, body.Project, "packet.import", digest); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return digest, nil
}
