package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type jsonMapTransport map[string]interface{}

func (m jsonMapTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	resp := &http.Response{}
	data, ok := m[request.URL.Path]
	if !ok {
		resp.StatusCode = http.StatusNotFound
		resp.Body = io.NopCloser(bytes.NewReader([]byte("")))
		return resp, nil
	}
	resp.StatusCode = http.StatusOK
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	resp.Header = http.Header{
		"Content-Type":   []string{"application/json"},
		"Content-Length": []string{strconv.Itoa(len(raw))},
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	return resp, nil
}

func TestOauthJwKsParsing(t *testing.T) {
	c := &http.Client{
		Transport: jsonMapTransport{
			"/.well-known/openid-configuration": map[string]interface{}{
				"jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
			},
			"/oauth2/v3/certs": map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"e":   "AQAB",
						"alg": "RS256",
						"use": "sig",
						"n":   "rHz-FQE9gjFJR_FhnzhBMPpa8NJ2nCfnXLr5LWDJOOaiGqI__Nrm6HHUCpMi52_pLqqVkCihR9xbscZ6UKr9wjp-7YTDN6A9i7QqQAJyNRIMCkJR1z6D95_pam_mIkBVnYjJ_LskOyOHI65Yvuaw6oA9iFlSyucn4B-jZRmp7JyGyU8UMohaOvJB7_boaIoEx_QY8YdoANKrp0WGawEkW6RgopgiHB7D0CXU-c_GDp0TjWCZegQzoV_fDD5eH5mc2Ai3dBylZxgQ-ZxMakYS01nmVr1atkpHT1L9W7PiCP60C8WG1aLIzZTLcABK3BWCmZ3-wBZtHZ0y9kSP35aowQ",
						"kty": "RSA",
						"kid": "b509c5138768f7cf2e827e04b27e7e4cbc7bb919",
					},
					{
						"kty": "RSA",
						"kid": "dd5301204fc1d6a0d68c783a35cc9c10b25e1f4a",
						"n":   "u0baiunQjQF5arG5MA3iKWQziu7NrzajO0ShUMwAcS9n2Ccu3SDwZFjdm6we7HzajGCWgysVlQKz8KcMC4LgBoN2zZHmzevxEC92ahMmuWy45oAHmfCv42yOPsp2GuxZf9xC7A_5AWImDgvWDCgs1X2Xkku91TOZjDsq4Oji6sMD8V18B7FD_hdY_RE1R6nw8ECLPtxdJC70WQVWaP24I3NQ2pF7wkzEgOJknWoYMCMpihljChvIWOxDf9qs7E7iws-xjPWdG2vltVAXuf9IVY3OU4PLTfzt8TXoqrpqEIq3-vlR8xEY0AB1kNic_rJerSwgmH5Sk-uDZuSwZQZvoQ",
						"use": "sig",
						"e":   "AQAB",
						"alg": "RS256",
					},
				},
			},
		},
	}

	u, err := getJwksUriFromOpenIdConfig(t.Context(), c, "https://accounts.google.com/.well-known/openid-configuration")
	require.NoError(t, err)
	assert.Equal(t, "https://www.googleapis.com/oauth2/v3/certs", u)

	rawKeys, err := getRawJwksKeys(t.Context(), c, u)
	require.NoError(t, err)
	assert.Len(t, rawKeys, 2)

	for _, rk := range rawKeys {
		require.NoError(t, err)
		rrk := rk.(*rsa.PublicKey)
		assert.Greater(t, rrk.N.BitLen(), 1024)
		assert.Greater(t, rrk.E, 1024)
		_, err = rsa.EncryptPKCS1v15(rand.Reader, rrk, []byte("test")) //nolint:staticcheck
		require.NoError(t, err)
	}
}
