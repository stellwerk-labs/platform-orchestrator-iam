package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

type TokenSource interface {
	Token(orgId string) string
}

type HmacTokenSource struct {
	Salt string
}

func (h *HmacTokenSource) Token(orgId string) string {
	hash := hmac.New(sha256.New, []byte(h.Salt))
	hash.Write([]byte(orgId))
	sum := hash.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum)
}
