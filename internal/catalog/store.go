package catalog

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

const MaxObjectBytes = 1 << 20

var ErrConflict = errors.New("catalog conflict")
var ErrNotFound = errors.New("catalog object not found")
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Record is an immutable observation. It never grants execution or trust authority.
type Record struct {
	Project string          `json:"project"`
	Site    string          `json:"site,omitempty"`
	Kind    string          `json:"kind"`
	Body    json.RawMessage `json:"body"`
}

type StoredRecord struct {
	Digest     string `json:"digest"`
	Record     Record `json:"record"`
	ImportedAt string `json:"importedAt"`
}

type Preview struct {
	Digest    string          `json:"digest"`
	Owner     string          `json:"owner"`
	Project   string          `json:"project"`
	Site      string          `json:"site,omitempty"`
	Purpose   string          `json:"purpose"`
	Policy    string          `json:"policy"`
	Payload   json.RawMessage `json:"payload"`
	ExpiresAt string          `json:"expiresAt"`
}

type AuditEvent struct {
	ID        int64  `json:"id"`
	Actor     string `json:"actor"`
	Project   string `json:"project"`
	Action    string `json:"action"`
	Digest    string `json:"digest"`
	CreatedAt string `json:"createdAt"`
}

type Store struct {
	db     *sql.DB
	driver string
}

func Open(ctx context.Context, driver, dsn string) (*Store, error) {
	if driver != "sqlite" && driver != "pgx" {
		return nil, fmt.Errorf("catalog driver must be sqlite or pgx")
	}
	if driver == "sqlite" && dsn != ":memory:" {
		if strings.HasPrefix(dsn, "file:") || strings.Contains(dsn, "?") {
			return nil, errors.New("SQLite catalog requires a plain filesystem path or :memory:")
		}
		if err := os.MkdirAll(filepath.Dir(dsn), 0700); err != nil {
			return nil, err
		}
		if info, err := os.Lstat(dsn); err == nil && !info.Mode().IsRegular() {
			return nil, errors.New("catalog database must be a regular file")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		f, err := os.OpenFile(dsn, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		if err = f.Chmod(0600); err != nil {
			f.Close()
			return nil, err
		}
		if err = f.Close(); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
	}
	s := &Store{db: db, driver: driver}
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect catalog: %w", err)
	}
	if driver == "sqlite" {
		for _, q := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL"} {
			if _, err = db.ExecContext(ctx, q); err != nil {
				db.Close()
				return nil, err
			}
		}
	}
	if err = s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	blob, serial := "BLOB", "INTEGER PRIMARY KEY AUTOINCREMENT"
	if s.driver == "pgx" {
		blob, serial = "BYTEA", "BIGSERIAL PRIMARY KEY"
	}
	queries := []string{
		`CREATE TABLE IF NOT EXISTS catalog_schema (version INTEGER PRIMARY KEY)`,
		`INSERT INTO catalog_schema(version) VALUES(1) ON CONFLICT DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS catalog_records (project TEXT NOT NULL, site TEXT NOT NULL, kind TEXT NOT NULL, digest TEXT NOT NULL, body ` + blob + ` NOT NULL, imported_at TEXT NOT NULL, PRIMARY KEY(project,site,kind,digest))`,
		`CREATE TABLE IF NOT EXISTS catalog_previews (digest TEXT PRIMARY KEY, owner TEXT NOT NULL, project TEXT NOT NULL, site TEXT NOT NULL, purpose TEXT NOT NULL, policy TEXT NOT NULL, payload ` + blob + ` NOT NULL, expires_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS catalog_streams (issuer TEXT NOT NULL, project TEXT NOT NULL, site TEXT NOT NULL, sequence BIGINT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(issuer,project,site))`,
		`CREATE TABLE IF NOT EXISTS catalog_imports (digest TEXT PRIMARY KEY, actor TEXT NOT NULL, imported_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS catalog_requests (actor TEXT NOT NULL, scope TEXT NOT NULL, request_key TEXT NOT NULL, digest TEXT NOT NULL, response ` + blob + ` NOT NULL, PRIMARY KEY(actor,scope,request_key))`,
		`CREATE TABLE IF NOT EXISTS catalog_notifications (id TEXT PRIMARY KEY, project TEXT NOT NULL, site TEXT NOT NULL, digest TEXT NOT NULL, body ` + blob + ` NOT NULL, exported_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS catalog_audit (id ` + serial + `, actor TEXT NOT NULL, project TEXT NOT NULL, action TEXT NOT NULL, digest TEXT NOT NULL, created_at TEXT NOT NULL)`,
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range queries {
		if _, err = tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("catalog migration: %w", err)
		}
	}
	var version int
	if err = tx.QueryRowContext(ctx, `SELECT MAX(version) FROM catalog_schema`).Scan(&version); err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("unsupported catalog schema %d", version)
	}
	return tx.Commit()
}

func canonical(v any) ([]byte, error) {
	return spec.Canonical(v)
}

func digestBytes(b []byte) string { return spec.Hash(b) }

func strictJSON(b []byte, v any) error {
	if len(b) > MaxObjectBytes {
		return errors.New("object exceeds size limit")
	}
	trim := bytes.TrimSpace(b)
	if len(trim) == 0 || trim[0] != '{' && trim[0] != '[' {
		return errors.New("expected JSON")
	}
	return spec.Decode(b, v)
}

func normalizeRecord(r Record) (Record, []byte, string, error) {
	if !identifier.MatchString(r.Project) || (r.Site != "" && !identifier.MatchString(r.Site)) {
		return r, nil, "", errors.New("invalid project or site identifier")
	}
	switch r.Kind {
	case "Release", "Site", "RunResult", "Plan", "TrustPolicy", "PolicyPack", "Approval", "Receipt", "Evidence":
	default:
		return r, nil, "", errors.New("unsupported catalog record kind")
	}
	if len(r.Body) == 0 || len(r.Body) > MaxObjectBytes {
		return r, nil, "", errors.New("invalid record body size")
	}
	var value map[string]json.RawMessage
	if err := strictJSON(r.Body, &value); err != nil || value == nil {
		return r, nil, "", errors.New("record body must be a valid JSON object without duplicate keys")
	}
	body, err := spec.CanonicalRaw(r.Body)
	if err != nil {
		return r, nil, "", err
	}
	r.Body = body
	if r.Kind == "PolicyPack" {
		var pack PolicyPack
		if err := strictJSON(body, &pack); err != nil {
			return r, nil, "", err
		}
		if err := validatePolicyPack(pack); err != nil {
			return r, nil, "", err
		}
	}
	b, err := canonical(r)
	if err != nil {
		return r, nil, "", err
	}
	return r, b, digestBytes(b), nil
}

func (s *Store) q(q string) string {
	if s.driver != "pgx" {
		return q
	}
	var b strings.Builder
	n := 0
	for _, c := range q {
		if c == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (s *Store) Put(ctx context.Context, actor string, r Record) (StoredRecord, error) {
	r, b, d, err := normalizeRecord(r)
	if err != nil {
		return StoredRecord{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return StoredRecord{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, s.q(`INSERT INTO catalog_records(project,site,kind,digest,body,imported_at) VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING`), r.Project, r.Site, r.Kind, d, b, now)
	if err != nil {
		return StoredRecord{}, err
	}
	if err = s.auditTx(ctx, tx, actor, r.Project, "record.register", d); err != nil {
		return StoredRecord{}, err
	}
	if err = tx.Commit(); err != nil {
		return StoredRecord{}, err
	}
	return s.Get(ctx, r.Project, r.Site, r.Kind, d)
}

func (s *Store) Get(ctx context.Context, project, site, kind, digest string) (StoredRecord, error) {
	var b []byte
	out := StoredRecord{Digest: digest}
	err := s.db.QueryRowContext(ctx, s.q(`SELECT body,imported_at FROM catalog_records WHERE project=? AND site=? AND kind=? AND digest=?`), project, site, kind, digest).Scan(&b, &out.ImportedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if err = strictJSON(b, &out.Record); err != nil {
		return out, fmt.Errorf("catalog integrity: %w", err)
	}
	if digestBytes(b) != digest {
		return out, errors.New("catalog record integrity mismatch")
	}
	return out, nil
}

func (s *Store) List(ctx context.Context, project, site, kind string) ([]StoredRecord, error) {
	q := `SELECT digest,body,imported_at FROM catalog_records WHERE project=?`
	args := []any{project}
	if site != "" {
		q += ` AND site=?`
		args = append(args, site)
	}
	if kind != "" {
		q += ` AND kind=?`
		args = append(args, kind)
	}
	q += ` ORDER BY imported_at DESC,digest LIMIT 1000`
	rows, err := s.db.QueryContext(ctx, s.q(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StoredRecord{}
	for rows.Next() {
		var r StoredRecord
		var b []byte
		if err = rows.Scan(&r.Digest, &b, &r.ImportedAt); err != nil {
			return nil, err
		}
		if digestBytes(b) != r.Digest {
			return nil, errors.New("catalog record integrity mismatch")
		}
		if err = strictJSON(b, &r.Record); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SavePreview(ctx context.Context, p Preview) error {
	b, err := canonical(p.Payload)
	if err != nil {
		return err
	}
	if digestBytes(b) != p.Digest {
		return errors.New("preview digest mismatch")
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO catalog_previews(digest,owner,project,site,purpose,policy,payload,expires_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`), p.Digest, p.Owner, p.Project, p.Site, p.Purpose, p.Policy, b, p.ExpiresAt)
	return err
}

func (s *Store) Preview(ctx context.Context, digest, owner, purpose, policy string) (Preview, error) {
	p := Preview{Digest: digest}
	var payload []byte
	err := s.db.QueryRowContext(ctx, s.q(`SELECT owner,project,site,purpose,policy,payload,expires_at FROM catalog_previews WHERE digest=? AND owner=? AND purpose=?`), digest, owner, purpose).Scan(&p.Owner, &p.Project, &p.Site, &p.Purpose, &p.Policy, &payload, &p.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	exp, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil {
		return p, err
	}
	if !time.Now().Before(exp) || p.Policy != policy {
		return p, fmt.Errorf("%w: preview expired or policy changed", ErrConflict)
	}
	if digestBytes(payload) != digest {
		return p, errors.New("preview integrity mismatch")
	}
	p.Payload = payload
	return p, nil
}

func (s *Store) auditTx(ctx context.Context, tx *sql.Tx, actor, project, action, digest string) error {
	_, err := tx.ExecContext(ctx, s.q(`INSERT INTO catalog_audit(actor,project,action,digest,created_at) VALUES(?,?,?,?,?)`), actor, project, action, digest, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) Audit(ctx context.Context, project string) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id,actor,project,action,digest,created_at FROM catalog_audit WHERE project=? ORDER BY id DESC LIMIT 1000`), project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err = rows.Scan(&e.ID, &e.Actor, &e.Project, &e.Action, &e.Digest, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
