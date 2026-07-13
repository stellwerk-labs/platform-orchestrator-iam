package spicedb

import (
	"context"
	_ "embed"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

//go:embed schema.zed
var schema string

func NewClient(spiceDBUrl, token string, logger *zap.Logger) (SpiceDB, error) {
	client, err := authzed.NewClient(spiceDBUrl, grpc.WithTransportCredentials(insecure.NewCredentials()), grpcutil.WithInsecureBearerToken(token))
	if err != nil {
		return nil, err
	}
	return &spicedb{
		client: client,
		logger: logger,
	}, nil
}

func (s *spicedb) WriteSchema(ctx context.Context) error {
	_, err := s.client.WriteSchema(ctx, &v1.WriteSchemaRequest{
		Schema: schema,
	})
	return err
}
