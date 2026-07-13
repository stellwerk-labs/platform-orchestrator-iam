package userid

import (
	"github.com/google/uuid"
)

// HumanUserVariant the variant constant stored in 4 bits.
const (
	HumanUserVariant   byte = 0b0001
	ServiceUserVariant byte = 0b0010
)

// InternalSystemUuid is the uid associated with the system user for any calls between services internally.
var InternalSystemUuid = uuid.UUID([16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

// NewHumanUserId generates an uuid7 with the last 4 bits of the 6th byte set to 0x1 to identify the sub variant.
// service users and other user types may have an alternative sub variant applied.
// See https://datatracker.ietf.org/doc/html/rfc9562#name-uuid-version-7 for the format. We're using the 4 bits that the
// ver field is not using (bits 52-55 in octet 6).
func NewHumanUserId() uuid.UUID {
	inner, err := uuid.NewV7()
	if err != nil {
		// should never happen in modern go
		panic(err)
	}
	inner[6] = (inner[6] & 0b11110000) | HumanUserVariant
	return inner
}

// NewServiceUserTokenId is the same as NewHumanUserId but uses a different sub variant.
func NewServiceUserTokenId() uuid.UUID {
	inner, err := uuid.NewV7()
	if err != nil {
		// should never happen in modern go
		panic(err)
	}
	inner[6] = (inner[6] & 0b11110000) | ServiceUserVariant
	return inner
}

// IsHumanUser returns whether the given user id is a human user (and not the system uid either)
func IsHumanUser(id uuid.UUID) bool {
	return id != InternalSystemUuid && id[6]&HumanUserVariant == HumanUserVariant
}

// IsServiceUser returns whether the given user id is a service user (and not the system uid either)
func IsServiceUser(id uuid.UUID) bool {
	return id != InternalSystemUuid && id[6]&ServiceUserVariant == ServiceUserVariant
}

// GenerateDisplayNameForUserId should be used by convention to determine the display name for a user id that we don't
// have a display name for.
func GenerateDisplayNameForUserId(id uuid.UUID) string {
	if IsHumanUser(id) {
		return "User"
	} else if IsServiceUser(id) {
		return "Service User"
	} else if id == InternalSystemUuid {
		return "System"
	}
	return "Unknown User"
}
