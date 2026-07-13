package worker

import "time"

const (
	MainConsumerName        = "main-consumer"
	MainConsumerConcurrency = 10
	MainConsumerMessageTtl  = time.Minute * 10
)
