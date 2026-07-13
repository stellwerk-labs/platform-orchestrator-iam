package api

import (
	"context"
	"testing"

	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"

	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestDismissPrompt(t *testing.T) {
	_, s, fin := MockServer(t)
	defer fin()

	uid := userid.NewHumanUserId()
	s.Database.(*mockmodel.MockDatabaser).EXPECT().DismissUserPrompt(gomock.Any(), gomock.Any(), uid, "test-prompt").Return(nil)

	ctx := context.WithValue(t.Context(), hecho.ContextKeyUserID, uid.String())

	r, err := s.DismissPrompt(ctx, DismissPromptRequestObject{
		UserId: uid,
		Params: DismissPromptParams{Id: "test-prompt"},
	})
	require.NoError(t, err)
	require.Equal(t, DismissPrompt204Response{}, r)
}
