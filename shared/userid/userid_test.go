package userid

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewHumanUserId(t *testing.T) {
	ref, _ := uuid.NewV7()
	for i := 0; i < 10; i++ {
		u := NewHumanUserId()
		t.Logf("NewHumanUserId() = %s", u)
		assert.Equal(t, ref.Version(), u.Version())
		assert.Equal(t, ref.Variant(), u.Variant())
		assert.Equal(t, uint8('1'), u.String()[15])
	}
}
