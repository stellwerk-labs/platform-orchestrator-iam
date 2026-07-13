package ssoprovider

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captureTransport struct {
	lastReq *http.Request
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.lastReq = req
	return &http.Response{StatusCode: 200}, nil
}

func TestTransportRewriter(t *testing.T) {
	sourceURL, _ := url.Parse("https://external.example.com")
	targetURL, _ := url.Parse("http://internal-service:8080")

	// Create a dummy transport to capture the modified request
	capture := &captureTransport{}
	rewriter := &transportRewriter{
		transport: capture,
		source:    sourceURL,
		target:    targetURL,
	}

	client := &http.Client{Transport: rewriter}

	tests := []struct {
		name           string
		inputURL       string
		expectedScheme string
		expectedHost   string
	}{
		{
			name:           "Rewrite matching external host",
			inputURL:       "https://external.example.com/path",
			expectedScheme: "http",
			expectedHost:   "internal-service:8080",
		},
		{
			name:           "Ignore non-matching host",
			inputURL:       "https://google.com/path",
			expectedScheme: "https",
			expectedHost:   "google.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tt.inputURL, nil)
			require.NoError(t, err)
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() {
				_ = resp.Body.Close()
			}()

			assert.Equal(t, tt.expectedScheme, capture.lastReq.URL.Scheme)
			assert.Equal(t, tt.expectedHost, capture.lastReq.URL.Host)
		})
	}
}
