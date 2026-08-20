package authorization

import (
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pkg/errors"
)

const policyInvalidationSubject = "platform-orchestrator-iam.authorization.policy.invalidate"

type PolicyInvalidationSubscription interface {
	Unsubscribe() error
}

type PolicyInvalidationBus interface {
	Publish(subject string, data []byte) error
	Subscribe(subject string, handler func(data []byte)) (PolicyInvalidationSubscription, error)
}

type natsPolicyInvalidationBus struct {
	connection *nats.Conn
}

func NewNATSPolicyInvalidationBus(connection *nats.Conn) PolicyInvalidationBus {
	return &natsPolicyInvalidationBus{connection: connection}
}

func (b *natsPolicyInvalidationBus) Publish(subject string, data []byte) error {
	return b.connection.Publish(subject, data)
}

func (b *natsPolicyInvalidationBus) Subscribe(subject string, handler func(data []byte)) (PolicyInvalidationSubscription, error) {
	subscription, err := b.connection.Subscribe(subject, func(message *nats.Msg) {
		handler(message.Data)
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to subscribe to authorization policy invalidations")
	}
	if err := b.connection.FlushTimeout(time.Second); err != nil {
		_ = subscription.Unsubscribe()
		return nil, errors.Wrap(err, "failed to activate authorization policy invalidation subscription")
	}
	return subscription, nil
}
