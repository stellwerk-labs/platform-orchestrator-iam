package integrationtests

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlive(t *testing.T) {
	t.Parallel()
	resp, err := http.DefaultClient.Get(mustInternalServerURL(t) + "/alive")
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	content, _ := io.ReadAll(resp.Body)
	if assert.Equal(t, http.StatusOK, resp.StatusCode) {
		t.Logf("body: %s", string(content))
	} else {
		t.Logf("unexpected status code %d: %s", resp.StatusCode, string(content))
	}
}

func TestHealthy(t *testing.T) {
	t.Parallel()
	resp, err := http.DefaultClient.Get(mustInternalServerURL(t) + "/health")
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()
	content, _ := io.ReadAll(resp.Body)
	if assert.Equal(t, http.StatusOK, resp.StatusCode) {
		t.Logf("body: %s", string(content))
	} else {
		t.Logf("unexpected status code %d: %s", resp.StatusCode, string(content))
	}
}
