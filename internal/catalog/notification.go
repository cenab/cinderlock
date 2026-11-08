package catalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cenab/cinderlock/internal/spec"
	"github.com/cenab/cinderlock/internal/support"
)

// NotificationRule enables a local outbox only. No URL, email address, remote
// connector, or sending credential is accepted by this configuration.
type NotificationRule struct {
	ID      string   `json:"id"`
	Project string   `json:"project"`
	Site    string   `json:"site,omitempty"`
	States  []string `json:"states"`
}
type Notification struct {
	APIVersion   string          `json:"apiVersion"`
	Kind         string          `json:"kind"`
	ID           string          `json:"id"`
	RuleID       string          `json:"ruleID"`
	Project      string          `json:"project"`
	Site         string          `json:"site"`
	RecordDigest string          `json:"recordDigest"`
	Summary      support.Summary `json:"summary"`
	CreatedAt    string          `json:"createdAt"`
	Notice       string          `json:"notice"`
}
type QueuedNotification struct {
	Digest       string       `json:"digest"`
	Notification Notification `json:"notification"`
	ExportedAt   string       `json:"exportedAt,omitempty"`
}
type NotificationExport struct {
	APIVersion    string               `json:"apiVersion"`
	Kind          string               `json:"kind"`
	Owner         string               `json:"owner"`
	Notifications []QueuedNotification `json:"notifications"`
	Notice        string               `json:"notice"`
}

func validateNotificationRules(rules []NotificationRule) error {
	seen := map[string]bool{}
	for _, r := range rules {
		if !identifier.MatchString(r.ID) || seen[r.ID] || !identifier.MatchString(r.Project) || (r.Site != "" && !identifier.MatchString(r.Site)) || len(r.States) == 0 {
			return errors.New("notification rule needs a unique ID and explicit project/state scope")
		}
		seen[r.ID] = true
		for _, state := range r.States {
			if !contains([]string{"succeeded", "failed", "blocked", "needs_reconciliation", "recovered", "recovery_failed", "failed_lock", "interrupted", "artifacts_staged", "artifacts_failed"}, state) {
				return errors.New("unsupported notification run state")
			}
		}
	}
	return nil
}

func (s *Store) QueueNotifications(ctx context.Context, actor, project, site, recordDigest string, rules []NotificationRule, now time.Time) ([]QueuedNotification, error) {
	if !identifier.MatchString(actor) || !identifier.MatchString(project) || !identifier.MatchString(site) || !spec.ValidDigest(recordDigest) {
		return nil, errors.New("notification needs explicit actor, project, site, and record digest")
	}
	if err := validateNotificationRules(rules); err != nil {
		return nil, err
	}
	record, err := s.Get(ctx, project, site, "RunResult", recordDigest)
	if err != nil {
		return nil, err
	}
	var run spec.RunResult
	if err = strictJSON(record.Record.Body, &run); err != nil {
		return nil, err
	}
	if err = spec.ValidateHeader(run.Header, "RunResult"); err != nil {
		return nil, err
	}
	if run.SiteID != site || run.RunID == "" {
		return nil, errors.New("notification run site is not bound")
	}
	out := []QueuedNotification{}
	for _, rule := range rules {
		if rule.Project != project || (rule.Site != "" && rule.Site != site) || !contains(rule.States, run.State) {
			continue
		}
		id, err := spec.Digest(struct{ Rule, Record string }{rule.ID, recordDigest})
		if err != nil {
			return nil, err
		}
		note := Notification{APIVersion: spec.APIVersion, Kind: "LocalNotification", ID: id, RuleID: rule.ID, Project: project, Site: site, RecordDigest: recordDigest, Summary: support.Summarize(run), CreatedAt: now.UTC().Format(time.RFC3339Nano), Notice: "Local queued observation; no message was sent and this is not live health."}
		body, err := canonical(note)
		if err != nil {
			return nil, err
		}
		if len(body) > MaxObjectBytes {
			return nil, errors.New("notification exceeds size limit")
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, s.q(`INSERT INTO catalog_notifications(id,project,site,digest,body,exported_at) VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING`), id, project, site, spec.Hash(body), body, "")
		if err == nil {
			err = s.auditTx(ctx, tx, actor, project, "notification.queue", id)
		}
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		stored, err := s.notification(ctx, project, site, id)
		if err != nil {
			return nil, err
		}
		out = append(out, stored)
	}
	return out, nil
}

func scanNotification(row interface{ Scan(...any) error }) (QueuedNotification, error) {
	var out QueuedNotification
	var body []byte
	if err := row.Scan(&out.Digest, &body, &out.ExportedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return out, ErrNotFound
		}
		return out, err
	}
	if spec.Hash(body) != out.Digest {
		return out, errors.New("notification integrity mismatch")
	}
	if err := strictJSON(body, &out.Notification); err != nil {
		return out, err
	}
	return out, nil
}
func (s *Store) notification(ctx context.Context, project, site, id string) (QueuedNotification, error) {
	return scanNotification(s.db.QueryRowContext(ctx, s.q(`SELECT digest,body,exported_at FROM catalog_notifications WHERE project=? AND site=? AND id=?`), project, site, id))
}
func (s *Store) PendingNotifications(ctx context.Context, project, site string) ([]QueuedNotification, error) {
	if !identifier.MatchString(project) || !identifier.MatchString(site) {
		return nil, errors.New("notification project and site required")
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT digest,body,exported_at FROM catalog_notifications WHERE project=? AND site=? AND exported_at='' ORDER BY id LIMIT 128`), project, site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QueuedNotification{}
	for rows.Next() {
		n, err := scanNotification(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) NotificationPreview(ctx context.Context, actor, policy, project, site string, ids []string, now time.Time) (Preview, error) {
	if !identifier.MatchString(actor) || !spec.ValidDigest(policy) || len(ids) == 0 || len(ids) > 128 {
		return Preview{}, errors.New("notification preview needs an actor, policy, and exact pending IDs")
	}
	export := NotificationExport{APIVersion: spec.APIVersion, Kind: "LocalNotificationExport", Owner: actor, Notifications: []QueuedNotification{}, Notice: "Approved local outbox export only. No external delivery has occurred."}
	seen := map[string]bool{}
	totalBytes := 0
	for _, id := range ids {
		if !spec.ValidDigest(id) || seen[id] {
			return Preview{}, errors.New("invalid or duplicate notification ID")
		}
		seen[id] = true
		n, err := s.notification(ctx, project, site, id)
		if err != nil {
			return Preview{}, err
		}
		if n.ExportedAt != "" {
			return Preview{}, fmt.Errorf("%w: notification already exported", ErrConflict)
		}
		encoded, err := canonical(n)
		if err != nil {
			return Preview{}, err
		}
		totalBytes += len(encoded)
		if totalBytes > MaxObjectBytes {
			return Preview{}, errors.New("notification selection exceeds preview size limit")
		}
		export.Notifications = append(export.Notifications, n)
	}
	body, err := canonical(export)
	if err != nil {
		return Preview{}, err
	}
	if len(body) > MaxObjectBytes {
		return Preview{}, errors.New("notification preview exceeds size limit")
	}
	p := Preview{Digest: spec.Hash(body), Owner: actor, Project: project, Site: site, Purpose: "notification-export", Policy: policy, Payload: body, ExpiresAt: now.Add(15 * time.Minute).UTC().Format(time.RFC3339Nano)}
	if err = s.SavePreview(ctx, p); err != nil {
		return Preview{}, err
	}
	return p, nil
}

func (s *Store) ExportNotifications(ctx context.Context, actor, policy, previewDigest, approvedDigest string, now time.Time) (json.RawMessage, error) {
	if previewDigest != approvedDigest {
		return nil, errors.New("notification approval does not match the preview digest")
	}
	preview, err := s.Preview(ctx, previewDigest, actor, "notification-export", policy)
	if err != nil {
		return nil, err
	}
	var export NotificationExport
	if err = strictJSON(preview.Payload, &export); err != nil {
		return nil, err
	}
	if export.APIVersion != spec.APIVersion || export.Kind != "LocalNotificationExport" || export.Owner != actor || len(export.Notifications) == 0 {
		return nil, errors.New("invalid notification export")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, n := range export.Notifications {
		if n.Notification.Project != preview.Project || n.Notification.Site != preview.Site || n.ExportedAt != "" {
			return nil, errors.New("notification export scope mismatch")
		}
		body, err := canonical(n.Notification)
		if err != nil || spec.Hash(body) != n.Digest {
			return nil, errors.New("notification preview integrity mismatch")
		}
		result, err := tx.ExecContext(ctx, s.q(`UPDATE catalog_notifications SET exported_at=? WHERE project=? AND site=? AND id=? AND digest=? AND exported_at=''`), now.UTC().Format(time.RFC3339Nano), preview.Project, preview.Site, n.Notification.ID, n.Digest)
		if err != nil {
			return nil, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		if count != 1 {
			return nil, fmt.Errorf("%w: pending notification changed", ErrConflict)
		}
	}
	if err = s.auditTx(ctx, tx, actor, preview.Project, "notification.export", previewDigest); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return preview.Payload, nil
}

func (s *Server) mutateNotification(ctx context.Context, a Actor, path string, b []byte) (any, error) {
	if path == "/api/v1/notification-exports" {
		var request struct {
			Preview        string `json:"preview"`
			ApprovedDigest string `json:"approvedDigest"`
		}
		if err := strictJSON(b, &request); err != nil {
			return nil, err
		}
		p, err := s.cfg.Store.Preview(ctx, request.Preview, a.ID, "notification-export", s.policy)
		if err != nil {
			return nil, err
		}
		if !a.can(p.Project, p.Site, "export") {
			return nil, errDenied
		}
		payload, err := s.cfg.Store.ExportNotifications(ctx, a.ID, s.policy, request.Preview, request.ApprovedDigest, s.cfg.Now())
		return map[string]any{"state": "exported_locally", "payload": payload, "sent": false}, err
	}
	var request struct {
		Project   string   `json:"project"`
		Site      string   `json:"site"`
		RunDigest string   `json:"runDigest,omitempty"`
		IDs       []string `json:"ids,omitempty"`
	}
	if err := strictJSON(b, &request); err != nil {
		return nil, err
	}
	action := "import"
	if path == "/api/v1/notification-previews" {
		action = "export"
	}
	if !a.can(request.Project, request.Site, action) {
		return nil, errDenied
	}
	if path == "/api/v1/notification-queues" {
		return s.cfg.Store.QueueNotifications(ctx, a.ID, request.Project, request.Site, request.RunDigest, s.cfg.NotificationRules, s.cfg.Now())
	}
	return s.cfg.Store.NotificationPreview(ctx, a.ID, s.policy, request.Project, request.Site, request.IDs, s.cfg.Now())
}
