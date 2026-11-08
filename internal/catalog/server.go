package catalog

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/support"
)

type Actor struct {
	ID        string              `json:"id"`
	TokenHash string              `json:"tokenHash,omitempty"`
	Projects  map[string][]string `json:"projects"`
	Sites     []string            `json:"sites,omitempty"`
}

type Config struct {
	Store             *Store
	Actors            []Actor
	PacketKeys        []PacketKey
	Origin            string
	OIDC              *OIDCVerifier
	Now               func() time.Time
	NotificationRules []NotificationRule
	EvidenceKeys      []EvidenceKey
}

type Server struct {
	cfg    Config
	policy string
	ui     *template.Template
}

func TokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func NewHandler(cfg Config) (http.Handler, error) {
	if cfg.Store == nil || len(cfg.Actors) == 0 && cfg.OIDC == nil {
		return nil, errors.New("catalog requires a store and explicit identities")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := validateNotificationRules(cfg.NotificationRules); err != nil {
		return nil, err
	}
	if err := validateEvidenceKeys(cfg.EvidenceKeys); err != nil {
		return nil, err
	}
	cfg.EvidenceKeys = append([]EvidenceKey(nil), cfg.EvidenceKeys...)
	for i := range cfg.EvidenceKeys {
		k := &cfg.EvidenceKeys[i]
		k.Versions = append([]string(nil), k.Versions...)
		k.Projects = append([]string(nil), k.Projects...)
		k.Sites = append([]string(nil), k.Sites...)
		k.Applications = append([]string(nil), k.Applications...)
		k.Profiles = append([]string(nil), k.Profiles...)
		k.Scopes = append([]string(nil), k.Scopes...)
	}
	cfg.NotificationRules = append([]NotificationRule(nil), cfg.NotificationRules...)
	for i := range cfg.NotificationRules {
		cfg.NotificationRules[i].States = append([]string(nil), cfg.NotificationRules[i].States...)
	}
	seen := map[string]bool{}
	cfg.Actors = append([]Actor(nil), cfg.Actors...)
	for i, a := range cfg.Actors {
		if !identifier.MatchString(a.ID) || seen[a.ID] {
			return nil, errors.New("invalid or duplicate catalog actor")
		}
		seen[a.ID] = true
		if err := validateActor(a, true); err != nil {
			return nil, err
		}
		cfg.Actors[i] = cloneActor(a)
	}
	keys := append([]PacketKey(nil), cfg.PacketKeys...)
	for i := range keys {
		keys[i].Projects = append([]string(nil), keys[i].Projects...)
		keys[i].Sites = append([]string(nil), keys[i].Sites...)
		keys[i].Kinds = append([]string(nil), keys[i].Kinds...)
	}
	cfg.PacketKeys = keys
	if cfg.Origin != "" {
		u, e := url.Parse(cfg.Origin)
		if e != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return nil, errors.New("origin must be scheme and host only")
		}
		if u.Scheme != "https" && !isLoopback(u.Hostname()) {
			return nil, errors.New("remote catalog origin requires HTTPS")
		}
	}
	policyActors := make([]Actor, 0, len(cfg.Actors))
	for _, a := range cfg.Actors {
		a.TokenHash = ""
		policyActors = append(policyActors, a)
	}
	oidcScope := ""
	if cfg.OIDC != nil {
		oidcScope = cfg.OIDC.scope
	}
	b, err := canonical(struct {
		Actors        []Actor            `json:"actors"`
		Keys          []PacketKey        `json:"keys"`
		OIDC          string             `json:"oidc"`
		Notifications []NotificationRule `json:"notifications"`
		EvidenceKeys  []EvidenceKey      `json:"evidenceKeys"`
	}{policyActors, cfg.PacketKeys, oidcScope, cfg.NotificationRules, cfg.EvidenceKeys})
	if err != nil {
		return nil, err
	}
	t, err := template.New("catalog").Parse(dashboardTemplate)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, policy: digestBytes(b), ui: t}
	return http.HandlerFunc(s.serve), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ListenAddress refuses accidental public listeners. TLS termination is an explicit deployment decision.
func ListenAddress(address string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if !isLoopback(host) && !allowRemote {
		return errors.New("non-loopback catalog binding requires explicit remote/TLS configuration")
	}
	return nil
}

func (s *Server) authenticate(r *http.Request) (Actor, error) {
	header := r.Header.Get("Authorization")
	token := ""
	if strings.HasPrefix(header, "Bearer ") {
		token = strings.TrimPrefix(header, "Bearer ")
	}
	if _, password, ok := r.BasicAuth(); ok {
		token = password
	}
	if token == "" || len(token) > 16384 {
		return Actor{}, errors.New("authentication required")
	}
	hash := TokenHash(token)
	for _, a := range s.cfg.Actors {
		if a.TokenHash != "" && subtle.ConstantTimeCompare([]byte(hash), []byte(a.TokenHash)) == 1 {
			return a, nil
		}
	}
	if s.cfg.OIDC != nil {
		return s.cfg.OIDC.Verify(r.Context(), token)
	}
	return Actor{}, errors.New("authentication rejected")
}

func (a Actor) can(project, site, action string) bool {
	if len(a.Sites) > 0 && site != "" && !contains(a.Sites, site) {
		return false
	}
	for _, role := range a.Projects[project] {
		switch action {
		case "read":
			if contains([]string{"administrator", "publisher", "operator", "approver", "policy", "support", "auditor"}, role) {
				return true
			}
		case "publish":
			if role == "publisher" {
				return true
			}
		case "import", "export":
			if role == "operator" {
				return true
			}
		case "approve":
			if role == "approver" {
				return true
			}
		case "policy":
			if role == "policy" {
				return true
			}
		case "enroll":
			if role == "administrator" {
				return true
			}
		}
	}
	return false
}

func contains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

func validateActor(a Actor, local bool) error {
	if !identifier.MatchString(a.ID) || len(a.Projects) == 0 {
		return errors.New("actor needs an ID and explicit project bindings")
	}
	if local {
		b, e := hex.DecodeString(a.TokenHash)
		if e != nil || len(b) != 32 || strings.ToLower(a.TokenHash) != a.TokenHash {
			return errors.New("actor tokenHash must be lowercase SHA-256 hex")
		}
	} else if a.TokenHash != "" {
		return errors.New("OIDC subject must not carry a local token")
	}
	for project, roles := range a.Projects {
		if !identifier.MatchString(project) || len(roles) == 0 {
			return errors.New("invalid actor project binding")
		}
		seen := map[string]bool{}
		for _, role := range roles {
			if !contains([]string{"administrator", "publisher", "operator", "approver", "policy", "support", "auditor"}, role) || seen[role] {
				return errors.New("unknown or duplicate actor role")
			}
			seen[role] = true
		}
	}
	for _, site := range a.Sites {
		if !identifier.MatchString(site) {
			return errors.New("invalid actor site binding")
		}
	}
	return nil
}

func cloneActor(a Actor) Actor {
	out := a
	out.Sites = append([]string(nil), a.Sites...)
	out.Projects = map[string][]string{}
	for project, roles := range a.Projects {
		out.Projects[project] = append([]string(nil), roles...)
	}
	return out
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	actor, err := s.authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="Cinderlock", charset="UTF-8"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		if r.Header.Get("X-Cinderlock-Request") != "1" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "JSON request with X-Cinderlock-Request: 1 required", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && (s.cfg.Origin == "" || o != s.cfg.Origin) {
			http.Error(w, "origin rejected", http.StatusForbidden)
			return
		}
	}
	if r.Method == "GET" && r.URL.Path == "/" {
		s.dashboard(w, r, actor)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/v1/records" {
		s.list(w, r, actor)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/v1/audit" {
		s.audit(w, r, actor)
		return
	}
	if r.Method == "GET" && (r.URL.Path == "/api/v1/comparisons" || r.URL.Path == "/comparisons") {
		s.comparison(w, r, actor)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/v1/notifications" {
		project, site := r.URL.Query().Get("project"), r.URL.Query().Get("site")
		if !actor.can(project, site, "read") || onlySupport(actor, project) {
			s.fail(w, errDenied)
			return
		}
		notifications, err := s.cfg.Store.PendingNotifications(r.Context(), project, site)
		if err != nil {
			s.fail(w, err)
			return
		}
		s.json(w, notifications)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/api/v1/external-evidence" {
		project, site := r.URL.Query().Get("project"), r.URL.Query().Get("site")
		if !actor.can(project, site, "read") || onlySupport(actor, project) {
			s.fail(w, errDenied)
			return
		}
		verified, err := s.cfg.Store.VerifyEvidence(r.Context(), project, site, r.URL.Query().Get("digest"), s.cfg.EvidenceKeys, s.cfg.Now())
		if err != nil {
			s.fail(w, err)
			return
		}
		s.json(w, verified)
		return
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v1/projects/") && strings.HasSuffix(r.URL.Path, "/releases") {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) == 5 {
			q := r.URL.Query()
			q.Set("project", parts[3])
			q.Set("kind", "Release")
			r.URL.RawQuery = q.Encode()
			s.list(w, r, actor)
			return
		}
	}
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxObjectBytes+1))
	if err != nil || len(body) > MaxObjectBytes {
		http.Error(w, "request exceeds limits", http.StatusRequestEntityTooLarge)
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if !identifier.MatchString(key) {
		http.Error(w, "valid Idempotency-Key required", http.StatusBadRequest)
		return
	}
	scope := r.URL.Path + "#" + s.policy
	if replay, ok, e := s.reserve(r.Context(), actor.ID, scope, key, digestBytes(body)); e != nil {
		s.fail(w, e)
		return
	} else if ok {
		s.json(w, replay)
		return
	}
	response, err := s.mutate(r.Context(), actor, r.URL.Path, body)
	if err != nil {
		s.fail(w, err)
		return
	}
	b, err := canonical(response)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err = s.remember(r.Context(), actor.ID, scope, key, digestBytes(body), b); err != nil {
		s.fail(w, err)
		return
	}
	s.json(w, json.RawMessage(b))
}

var errDenied = errors.New("catalog scope or role rejected")

func (s *Server) mutate(ctx context.Context, a Actor, path string, b []byte) (any, error) {
	switch path {
	case "/api/v1/external-evidence":
		return s.admitExternalEvidence(ctx, a, b)
	case "/api/v1/notification-queues", "/api/v1/notification-previews", "/api/v1/notification-exports":
		return s.mutateNotification(ctx, a, path, b)
	case "/api/v1/records", "/api/v1/plan-reviews", "/api/v1/policy-admissions", "/api/v1/site-enrollments":
		var record Record
		if err := strictJSON(b, &record); err != nil {
			return nil, err
		}
		for endpoint, kind := range map[string]string{"/api/v1/plan-reviews": "Plan", "/api/v1/policy-admissions": "TrustPolicy", "/api/v1/site-enrollments": "Site"} {
			if path == endpoint && record.Kind != kind {
				return nil, errors.New("record kind does not match endpoint")
			}
		}
		action := "publish"
		switch record.Kind {
		case "Plan":
			action = "import"
		case "TrustPolicy":
			action = "policy"
		case "Site":
			action = "enroll"
		case "RunResult", "Receipt", "Evidence":
			action = "import"
		case "Approval":
			return nil, errors.New("use the approval endpoint")
		}
		if !a.can(record.Project, record.Site, action) {
			return nil, errDenied
		}
		return s.cfg.Store.Put(ctx, a.ID, record)
	case "/api/v1/import-previews":
		var packet Packet
		if err := strictJSON(b, &packet); err != nil {
			return nil, err
		}
		pb, _, err := VerifyPacket(packet, s.cfg.PacketKeys)
		if err != nil {
			return nil, err
		}
		if !a.can(pb.Project, pb.Site, "import") {
			return nil, errDenied
		}
		if err = packetRoles(a, pb); err != nil {
			return nil, err
		}
		data, err := canonical(packet)
		if err != nil {
			return nil, err
		}
		p := Preview{Digest: digestBytes(data), Owner: a.ID, Project: pb.Project, Site: pb.Site, Purpose: "import", Policy: s.policy, Payload: data, ExpiresAt: s.cfg.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339Nano)}
		if err = s.cfg.Store.SavePreview(ctx, p); err != nil {
			return nil, err
		}
		return p, nil
	case "/api/v1/imports":
		var request struct {
			Preview string `json:"preview"`
		}
		if err := strictJSON(b, &request); err != nil {
			return nil, err
		}
		p, err := s.cfg.Store.Preview(ctx, request.Preview, a.ID, "import", s.policy)
		if err != nil {
			return nil, err
		}
		if !a.can(p.Project, p.Site, "import") {
			return nil, errDenied
		}
		var packet Packet
		if err = strictJSON(p.Payload, &packet); err != nil {
			return nil, err
		}
		body, _, err := VerifyPacket(packet, s.cfg.PacketKeys)
		if err != nil {
			return nil, err
		}
		if err = packetRoles(a, body); err != nil {
			return nil, err
		}
		digest, err := s.cfg.Store.Import(ctx, a.ID, packet, s.cfg.PacketKeys)
		return map[string]string{"digest": digest, "state": "imported"}, err
	case "/api/v1/export-previews":
		var request struct {
			Project string   `json:"project"`
			Site    string   `json:"site"`
			Kind    string   `json:"kind"`
			Digests []string `json:"digests"`
		}
		if err := strictJSON(b, &request); err != nil {
			return nil, err
		}
		if !a.can(request.Project, request.Site, "export") {
			return nil, errDenied
		}
		if len(request.Digests) == 0 || len(request.Digests) > 128 {
			return nil, errors.New("select 1 to 128 exact record digests")
		}
		records := []Projection{}
		for _, d := range request.Digests {
			record, err := s.cfg.Store.Get(ctx, request.Project, request.Site, request.Kind, d)
			if err != nil {
				return nil, err
			}
			projection, err := projectRecord(record)
			if err != nil {
				return nil, err
			}
			records = append(records, projection)
		}
		data, err := canonical(records)
		if err != nil {
			return nil, err
		}
		p := Preview{Digest: digestBytes(data), Owner: a.ID, Project: request.Project, Site: request.Site, Purpose: "export", Policy: s.policy, Payload: data, ExpiresAt: s.cfg.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339Nano)}
		if err = s.cfg.Store.SavePreview(ctx, p); err != nil {
			return nil, err
		}
		return p, nil
	case "/api/v1/exports":
		var request struct {
			Preview string `json:"preview"`
		}
		if err := strictJSON(b, &request); err != nil {
			return nil, err
		}
		p, err := s.cfg.Store.Preview(ctx, request.Preview, a.ID, "export", s.policy)
		if err != nil {
			return nil, err
		}
		if !a.can(p.Project, p.Site, "export") {
			return nil, errDenied
		}
		return map[string]any{"digest": p.Digest, "records": p.Payload, "notice": "Reviewed local export only; not uploaded or execution authority"}, nil
	case "/api/v1/approvals":
		var request ApprovalRequest
		if err := strictJSON(b, &request); err != nil {
			return nil, err
		}
		if !a.can(request.Project, request.Site, "approve") {
			return nil, errDenied
		}
		plan, err := s.cfg.Store.Get(ctx, request.Project, request.Site, "Plan", request.PlanRecordDigest)
		if err != nil {
			return nil, err
		}
		var stored spec.Plan
		if err = strictJSON(plan.Record.Body, &stored); err != nil {
			return nil, errors.New("plan review must contain the original complete Plan")
		}
		if err = spec.ValidateHeader(stored.Header, "Plan"); err != nil {
			return nil, err
		}
		planDigest, err := spec.Digest(stored)
		if err != nil {
			return nil, err
		}
		actions := []string{}
		for _, op := range stored.Operations {
			if !contains(actions, op.Type) {
				actions = append(actions, op.Type)
			}
		}
		if !stored.Executable || request.PlanDigest != planDigest || request.PolicyDigest != stored.PolicyDigest || request.PolicyEpoch != stored.PolicyEpoch || request.TargetID != stored.Snapshot.TargetID || !sameStrings(request.Actions, actions) {
			return nil, fmt.Errorf("%w: approval differs from registered executable plan", ErrConflict)
		}
		policies, err := s.cfg.Store.List(ctx, request.Project, request.Site, "TrustPolicy")
		if err != nil {
			return nil, err
		}
		if len(policies) == 0 {
			return nil, fmt.Errorf("%w: no current policy observation admitted", ErrConflict)
		}
		var current spec.TrustPolicy
		if err = strictJSON(policies[0].Record.Body, &current); err != nil {
			return nil, err
		}
		if err = spec.ValidatePolicy(current); err != nil {
			return nil, err
		}
		currentDigest, err := spec.Digest(current)
		if err != nil {
			return nil, err
		}
		if currentDigest != request.PolicyDigest || current.Spec.Epoch != request.PolicyEpoch {
			return nil, fmt.Errorf("%w: current policy differs from reviewed plan", ErrConflict)
		}
		exp, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
		if err != nil || !s.cfg.Now().Before(exp) {
			return nil, errors.New("approval expiry required")
		}
		payload, err := canonical(struct {
			Decision   ApprovalRequest `json:"decision"`
			Actor      string          `json:"actor"`
			RecordedAt string          `json:"recordedAt"`
			Notice     string          `json:"notice"`
		}{request, a.ID, s.cfg.Now().UTC().Format(time.RFC3339Nano), "Catalog review record; not a signed execution Authorization"})
		if err != nil {
			return nil, err
		}
		return s.cfg.Store.Put(ctx, a.ID, Record{Project: request.Project, Site: request.Site, Kind: "Approval", Body: payload})
	default:
		return nil, ErrNotFound
	}
}

type ApprovalRequest struct {
	Project          string   `json:"project"`
	Site             string   `json:"site"`
	PlanRecordDigest string   `json:"planRecordDigest"`
	PlanDigest       string   `json:"planDigest"`
	PolicyDigest     string   `json:"policyDigest"`
	PolicyEpoch      int64    `json:"policyEpoch"`
	TargetID         string   `json:"targetID"`
	Actions          []string `json:"actions"`
	ExpiresAt        string   `json:"expiresAt"`
}

func packetRoles(a Actor, body PacketBody) error {
	for _, r := range body.Records {
		action := "import"
		switch r.Kind {
		case "TrustPolicy":
			action = "policy"
		case "Approval":
			action = "approve"
		case "Site":
			action = "enroll"
		}
		if !a.can(body.Project, body.Site, action) {
			return errDenied
		}
	}
	return nil
}

func sameStrings(a, b []string) bool {
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, a Actor) {
	project, site, kind := r.URL.Query().Get("project"), r.URL.Query().Get("site"), r.URL.Query().Get("kind")
	if !a.can(project, site, "read") {
		s.fail(w, errDenied)
		return
	}
	records, err := s.cfg.Store.List(r.Context(), project, site, kind)
	if err != nil {
		s.fail(w, err)
		return
	}
	filtered := []any{}
	for _, record := range records {
		if a.can(project, record.Record.Site, "read") {
			if onlySupport(a, project) {
				projection, err := projectRecord(record)
				if err != nil {
					s.fail(w, err)
					return
				}
				filtered = append(filtered, projection)
			} else {
				filtered = append(filtered, record)
			}
		}
	}
	s.json(w, filtered)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request, a Actor) {
	project := r.URL.Query().Get("project")
	if !a.can(project, "", "read") {
		s.fail(w, errDenied)
		return
	}
	if len(a.Sites) > 0 {
		s.fail(w, errDenied)
		return
	}
	events, err := s.cfg.Store.Audit(r.Context(), project)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.json(w, events)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, a Actor) {
	type view struct {
		Actor    string
		Records  []StoredRecord
		Projects []string
	}
	v := view{Actor: a.ID, Records: []StoredRecord{}}
	for project := range a.Projects {
		v.Projects = append(v.Projects, project)
	}
	sort.Strings(v.Projects)
	for _, project := range v.Projects {
		records, err := s.cfg.Store.List(r.Context(), project, "", "")
		if err != nil {
			s.fail(w, err)
			return
		}
		for _, record := range records {
			if a.can(project, record.Record.Site, "read") {
				if onlySupport(a, project) {
					projection, err := projectRecord(record)
					if err != nil {
						s.fail(w, err)
						return
					}
					record.Record.Body = projection.Body
					record.Record.Site = ""
				}
				v.Records = append(v.Records, record)
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.ui.Execute(w, v); err != nil {
		return
	}
}

func (s *Server) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func (s *Server) fail(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	if errors.Is(err, errDenied) {
		code = http.StatusForbidden
	} else if errors.Is(err, ErrConflict) {
		code = http.StatusConflict
	} else if errors.Is(err, ErrNotFound) {
		code = http.StatusNotFound
	}
	http.Error(w, http.StatusText(code), code)
}

func (s *Server) reserve(ctx context.Context, actor, scope, key, digest string) (json.RawMessage, bool, error) {
	r, err := s.cfg.Store.db.ExecContext(ctx, s.cfg.Store.q(`INSERT INTO catalog_requests(actor,scope,request_key,digest,response) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING`), actor, scope, key, digest, []byte{})
	if err != nil {
		return nil, false, err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	if n == 1 {
		return nil, false, nil
	}
	var old string
	var response []byte
	err = s.cfg.Store.db.QueryRowContext(ctx, s.cfg.Store.q(`SELECT digest,response FROM catalog_requests WHERE actor=? AND scope=? AND request_key=?`), actor, scope, key).Scan(&old, &response)
	if err != nil {
		return nil, false, err
	}
	if old != digest {
		return nil, false, fmt.Errorf("%w: idempotency key reused for different input", ErrConflict)
	}
	if len(response) == 0 {
		return nil, false, fmt.Errorf("%w: prior metadata request pending; inspect records before a new attempt", ErrConflict)
	}
	return response, true, nil
}
func (s *Server) remember(ctx context.Context, actor, scope, key, digest string, response []byte) error {
	r, err := s.cfg.Store.db.ExecContext(ctx, s.cfg.Store.q(`UPDATE catalog_requests SET response=? WHERE actor=? AND scope=? AND request_key=? AND digest=?`), response, actor, scope, key, digest)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

type Projection struct {
	SourceDigest string          `json:"sourceDigest"`
	Project      string          `json:"project"`
	Kind         string          `json:"kind"`
	Body         json.RawMessage `json:"body"`
}

func onlySupport(a Actor, project string) bool {
	roles := a.Projects[project]
	return len(roles) == 1 && roles[0] == "support"
}

func projectRecord(record StoredRecord) (Projection, error) {
	out := Projection{SourceDigest: record.Digest, Project: record.Record.Project, Kind: record.Record.Kind}
	if record.Record.Kind == "RunResult" {
		var run spec.RunResult
		if err := strictJSON(record.Record.Body, &run); err != nil {
			return out, err
		}
		b, err := canonical(support.Summarize(run))
		out.Body = b
		return out, err
	}
	var fields map[string]json.RawMessage
	if err := strictJSON(record.Record.Body, &fields); err != nil {
		return out, err
	}
	summary := map[string]json.RawMessage{}
	for _, key := range []string{"apiVersion", "kind", "schemaVersion", "bundleDigest", "planDigest", "policyDigest", "policyEpoch", "sourceVersion", "targetVersion", "version", "channel", "sequence", "state", "acceptance"} {
		if b, ok := fields[key]; ok {
			var value any
			if err := json.Unmarshal(b, &value); err != nil {
				return out, err
			}
			switch value.(type) {
			case string, float64, bool, nil:
				summary[key] = b
			}
		}
	}
	if raw, ok := fields["metadata"]; ok {
		var metadata map[string]json.RawMessage
		if err := strictJSON(raw, &metadata); err != nil {
			return out, err
		}
		selected := map[string]json.RawMessage{}
		for _, key := range []string{"application", "version", "channel", "sequence"} {
			if value, ok := metadata[key]; ok {
				selected[key] = value
			}
		}
		b, err := canonical(selected)
		if err != nil {
			return out, err
		}
		summary["metadata"] = b
	}
	b, err := canonical(summary)
	out.Body = b
	return out, err
}

const dashboardTemplate = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Cinderlock release catalog</title><style>body{margin:0;background:#101a1c;color:#edf4f1;font:1rem/1.6 system-ui,sans-serif}main,header{max-width:76rem;margin:auto;padding:1.5rem}a{color:#8ff0cc}a:focus-visible,summary:focus-visible{outline:3px solid #fff;outline-offset:4px}.skip{position:absolute;left:-999px}.skip:focus{left:1rem;top:.5rem;background:#101a1c}h1{font-size:2.5rem;line-height:1.15}p{max-width:65ch}.records{display:grid;gap:1rem}article{border:1px solid #55736b;border-radius:.6rem;padding:1rem;min-width:0}dt{font-weight:bold}dd{margin:0 0 .5rem;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-width:100%}summary{cursor:pointer;padding:.5rem}code{overflow-wrap:anywhere}.note{border-left:4px solid #8ff0cc;padding:.75rem 1rem}.muted{color:#b6c9c3}</style></head><body><a class="skip" href="#main">Skip to records</a><header><p>CINDERLOCK / LOCAL RELEASE CATALOG</p><h1>Know what arrived.<br>Keep execution local.</h1><p class="muted">Signed in as {{.Actor}}. Catalog records are last-known observations, not live cluster health.</p></header><main id="main"><p class="note">Receipt, signature verification, and application acceptance are different results. No action on this page deploys an application.</p><nav aria-label="Catalog views">{{range .Projects}}<p><a href="/comparisons?project={{.}}">Compare recorded runs in {{.}}</a></p>{{end}}</nav><h2>Admitted records</h2><div class="records">{{range .Records}}<article><h3>{{.Record.Kind}}</h3><dl><dt>Project and site</dt><dd>{{.Record.Project}} / {{if .Record.Site}}{{.Record.Site}}{{else}}Project scope{{end}}</dd><dt>Identity</dt><dd><code>{{.Digest}}</code></dd><dt>Imported locally</dt><dd><time>{{.ImportedAt}}</time></dd></dl><details><summary>View original record</summary><pre>{{printf "%s" .Record.Body}}</pre></details></article>{{else}}<p>No records are visible under your assigned scope.</p>{{end}}</div><h2>Exchange and review</h2><p>Use the authenticated API to preview and admit signed packets. Review exports locally before moving them through your approved process. Execution approvals remain bound to the target's exact plan and policy.</p></main></body></html>`
