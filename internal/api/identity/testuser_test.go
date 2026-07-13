package identity

import (
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestTestUserProvider(t *testing.T) {
	k, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	tp, _ := NewTestUserProvider(k.String())

	displayName := "bob.smith"
	token := EncryptForTestUserProvider(IdentifiedUser{
		ProviderId:  "my-user-id",
		DisplayName: &displayName,
	}, k)

	t.Run("valid", func(t *testing.T) {
		iu, ok, err := tp.IdentifyUser(t.Context(), zaptest.NewLogger(t), token)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, "my-user-id", iu.ProviderId)
		require.Equal(t, "bob.smith", *iu.DisplayName)
	})

	t.Run("garbage", func(t *testing.T) {
		_, _, err := tp.IdentifyUser(t.Context(), zaptest.NewLogger(t), "bananas")
		require.EqualError(t, err, "failed to decrypt token: failed to read header: parsing age header: failed to read intro: unexpected EOF")
	})
}
