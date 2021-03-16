package routes_test

import (
	"goauth-extension/app/routes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthoriationRedirectesToConsentPage(t *testing.T) {
	server := httptest.NewServer(routes.AuthorizationRoutes())
	defer server.Close()

	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize", nil)
	q := req.URL.Query()
	q.Add("client_id", "TEST_CLIENT")
	q.Add("grant_type", "authorization_code")
	q.Add("redirect_uri", "http://test.client/oauth2-callback")
	q.Add("scope", "all")
	q.Add("state", "cliend-data")

	req.URL.RawQuery = q.Encode()

	resp, err := httpClient.Do(req)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/oauth2/consent", resp.Header.Get("Location"))
}
