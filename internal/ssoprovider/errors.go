package ssoprovider

import "github.com/pkg/errors"

type ErrBadRequest struct {
	Message string
}

func (e ErrBadRequest) Error() string {
	return e.Message
}

func IsErrBadRequest(err error) (ErrBadRequest, bool) {
	var e ErrBadRequest
	if errors.As(err, &e) {
		return e, true
	}
	return e, false
}
