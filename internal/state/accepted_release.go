package state

import "context"

func (s *Store) HasAcceptedRelease(ctx context.Context, target, application string) (bool, error) {
	var accepted bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM release_floors WHERE target_id=? AND application=?)`, target, application).Scan(&accepted)
	return accepted, err
}

func (s *Store) IsAcceptedRelease(ctx context.Context, target, application, channel string, sequence int64, digest string) (bool, error) {
	var accepted bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM release_floors WHERE target_id=? AND application=? AND channel=? AND sequence=? AND bundle_digest=?)`, target, application, channel, sequence, digest).Scan(&accepted)
	return accepted, err
}
