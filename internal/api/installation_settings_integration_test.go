//go:build integration

package api

import (
	"bytes"
	"testing"
	"time"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stretchr/testify/require"
)

func TestInstallationSessionPolicyChangesApplyWithoutResurrectingSessions(t *testing.T) {
	s, db, _, user := browserSessionFixture(t)
	require.NoError(t, model.InitializeInstallationSessionPolicy(t.Context(), s.Database, 15*time.Minute, 2*time.Hour, false))
	create := func(provider model.UserIdentityProvider, age time.Duration) ([]byte, time.Time) {
		t.Helper()
		_, token := s.newSessionToken(user, provider)
		token.CreatedAt = token.CreatedAt.Add(-age)
		token.ExpiresAt = token.CreatedAt.Add(24 * time.Hour)
		if provider == model.UserIdentityProviderDevice {
			token.ExpiresAt = token.CreatedAt.Add(2 * time.Hour)
		}
		_, err := s.Database.CreateSessionToken(t.Context(), nil, token)
		require.NoError(t, err)
		_, err = db.Exec(`UPDATE session_tokens SET last_active_at=statement_timestamp()-($1*interval '1 microsecond') WHERE sha256_hash=$2`, age.Microseconds(), token.Sha256Hash)
		require.NoError(t, err)
		return token.Sha256Hash, token.CreatedAt
	}
	expiredBrowser, _ := create(model.UserIdentityProviderGoogle, 20*time.Minute)
	activeBrowser, _ := create(model.UserIdentityProviderGoogle, 2*time.Minute)
	expiredCLI, _ := create(model.UserIdentityProviderDevice, 3*time.Hour)
	activeCLI, cliCreated := create(model.UserIdentityProviderDevice, time.Hour)
	policy, err := model.UpdateInstallationSessionPolicy(t.Context(), s.Database, user, 1, 30*time.Minute, 4*time.Hour, 15*time.Minute, 2*time.Hour)
	require.NoError(t, err)
	require.EqualValues(t, 2, policy.Revision)
	for _, hash := range [][]byte{expiredBrowser, expiredCLI} {
		_, err := s.Database.GetSessionTokenByHash(t.Context(), nil, hash)
		_, missing := model.IsErrNotFound(err)
		require.True(t, missing, "expired credential revived: %v", err)
	}
	token, err := s.Database.GetSessionTokenByHash(t.Context(), nil, activeBrowser)
	require.NoError(t, err)
	require.Equal(t, 30*time.Minute, token.BrowserIdleTimeout)
	token, err = s.Database.GetSessionTokenByHash(t.Context(), nil, activeCLI)
	require.NoError(t, err)
	require.WithinDuration(t, cliCreated.Add(4*time.Hour), token.ExpiresAt, time.Millisecond)
	_, err = model.UpdateInstallationSessionPolicy(t.Context(), s.Database, user, 1, time.Hour, time.Hour, 15*time.Minute, 2*time.Hour)
	require.ErrorIs(t, err, model.ErrSettingsRevision)
	_, err = model.UpdateInstallationSessionPolicy(t.Context(), s.Database, user, 2, time.Minute, 30*time.Minute, 15*time.Minute, 2*time.Hour)
	require.NoError(t, err)
	_, err = model.UpdateInstallationSessionPolicy(t.Context(), s.Database, user, 3, time.Hour, 8*time.Hour, 15*time.Minute, 2*time.Hour)
	require.NoError(t, err)
	for _, hash := range [][]byte{activeBrowser, activeCLI} {
		_, err := s.Database.GetSessionTokenByHash(t.Context(), nil, hash)
		_, missing := model.IsErrNotFound(err)
		require.True(t, missing)
	}
	require.NoError(t, model.InitializeInstallationSessionPolicy(t.Context(), s.Database, 10*time.Minute, time.Hour, false))
	policy, err = model.ReadInstallationSessionPolicy(t.Context(), s.Database, 15*time.Minute, 2*time.Hour)
	require.NoError(t, err)
	require.Equal(t, time.Hour, policy.BrowserIdleTimeout, "restart overwrote saved policy")
	require.NoError(t, model.InitializeInstallationSessionPolicy(t.Context(), s.Database, 10*time.Minute, time.Hour, true))
	policy, err = model.ReadInstallationSessionPolicy(t.Context(), s.Database, 15*time.Minute, 2*time.Hour)
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, policy.BrowserIdleTimeout)
	var events int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM installation_session_policy_events`).Scan(&events))
	require.Equal(t, 5, events)
}

func TestSessionPolicyUpdateSerializesWithActivityAndTokenIssuance(t *testing.T) {
	s, db, _, user := browserSessionFixture(t)
	require.NoError(t, model.InitializeInstallationSessionPolicy(t.Context(), s.Database, 15*time.Minute, 2*time.Hour, false))
	_, token := s.newSessionToken(user, model.UserIdentityProviderGoogle)
	_, err := s.Database.CreateSessionToken(t.Context(), nil, token)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE session_tokens SET last_active_at=statement_timestamp()-interval '2 minutes' WHERE sha256_hash=$1`, token.Sha256Hash)
	require.NoError(t, err)
	lock, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = lock.Rollback() }()
	_, err = lock.Exec(`SELECT sha256_hash FROM session_tokens WHERE sha256_hash=$1 FOR UPDATE`, token.Sha256Hash)
	require.NoError(t, err)
	update := make(chan error, 1)
	go func() {
		_, err := model.UpdateInstallationSessionPolicy(t.Context(), s.Database, user, 1, time.Minute, time.Hour, 15*time.Minute, 2*time.Hour)
		update <- err
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT count(*) FROM (SELECT sha256_hash FROM session_tokens%')`).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, 10*time.Millisecond)
	activity := make(chan error, 1)
	go func() {
		_, err := s.Database.RecordBrowserSessionActivity(t.Context(), token.Sha256Hash, 15*time.Minute)
		activity <- err
	}()
	require.NoError(t, lock.Commit())
	require.NoError(t, <-update)
	_, missing := model.IsErrNotFound(<-activity)
	require.True(t, missing, "old-policy activity revived a shortened session")
	_, cli := s.newSessionToken(user, model.UserIdentityProviderDevice)
	issued, err := s.Database.CreateSessionToken(t.Context(), nil, cli)
	require.NoError(t, err)
	require.Equal(t, time.Hour, issued.ExpiresAt.Sub(issued.CreatedAt))
}

func TestSessionPolicyDoesNotReviveSessionsExpiringWhileRowLocksWait(t *testing.T) {
	s, db, _, user := browserSessionFixture(t)
	require.NoError(t, model.InitializeInstallationSessionPolicy(t.Context(), s.Database, 15*time.Minute, 2*time.Hour, false))
	_, first := s.newSessionToken(user, model.UserIdentityProviderGoogle)
	first.Sha256Hash = make([]byte, 32)
	_, err := s.Database.CreateSessionToken(t.Context(), nil, first)
	require.NoError(t, err)
	_, second := s.newSessionToken(user, model.UserIdentityProviderDevice)
	second.Sha256Hash = bytes.Repeat([]byte{1}, 32)
	_, err = s.Database.CreateSessionToken(t.Context(), nil, second)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE session_tokens SET expires_at=statement_timestamp() AT TIME ZONE 'UTC'+interval '1 second' WHERE sha256_hash=$1`, second.Sha256Hash)
	require.NoError(t, err)
	lock, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = lock.Rollback() }()
	_, err = lock.Exec(`SELECT sha256_hash FROM session_tokens WHERE sha256_hash=$1 FOR UPDATE`, first.Sha256Hash)
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() {
		_, err := model.UpdateInstallationSessionPolicy(t.Context(), s.Database, user, 1, time.Hour, 8*time.Hour, 15*time.Minute, 2*time.Hour)
		result <- err
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT count(*) FROM (SELECT sha256_hash FROM session_tokens%')`).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, 10*time.Millisecond)
	authentication := make(chan error, 1)
	go func() {
		_, err := s.Database.GetSessionTokenByHash(t.Context(), nil, second.Sha256Hash)
		authentication <- err
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT revision FROM installation_session_policy%')`).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, 10*time.Millisecond)
	time.Sleep(1200 * time.Millisecond)
	require.NoError(t, lock.Commit())
	require.NoError(t, <-result)
	_, authMissing := model.IsErrNotFound(<-authentication)
	require.True(t, authMissing, "authentication did not wait for the policy's committed result")
	_, err = s.Database.GetSessionTokenByHash(t.Context(), nil, second.Sha256Hash)
	_, missing := model.IsErrNotFound(err)
	require.True(t, missing, "lengthened a token that expired during the lock wait")
}
