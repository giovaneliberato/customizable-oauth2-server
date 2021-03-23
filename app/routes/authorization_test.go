package routes_test

import (
	"encoding/json"
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/infra"
	"goauth-extension/app/routes"
	"goauth-extension/app/test"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidClientIDBadRequest(t *testing.T) {
	infra.InitializeApp()
	server := httptest.NewServer(routes.AuthorizationRouter())
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize", nil)
	q := req.URL.Query()
	q.Add("client_id", "invalid")
	q.Add("grant_type", "authorization_code")
	q.Add("redirect_uri", test.TestClient.AllowedRedirectUrls[0])
	q.Add("scope", "profile")
	q.Add("state", "client-data")

	req.URL.RawQuery = q.Encode()

	resp, _ := httpClient().Do(req)
	var respBody authorization.ValidationError

	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Equal(t, "invalid_client", respBody.Err)
}

func TestAuthoriationRedirects(t *testing.T) {
	infra.InitializeApp()
	server := httptest.NewServer(routes.AuthorizationRouter())
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize", nil)
	q := req.URL.Query()
	q.Add("client_id", test.TestClient.ID)
	q.Add("grant_type", "authorization_code")
	q.Add("redirect_uri", test.TestClient.AllowedRedirectUrls[0])
	q.Add("scope", "profile")
	q.Add("state", "client-data")

	req.URL.RawQuery = q.Encode()

	resp, _ := httpClient().Do(req)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs := url.Query()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/oauth2/authorize", url.Path)
	assert.Equal(t, "test-id", qs.Get("client_id"))
	assert.Equal(t, "profile", qs.Get("requested_scopes"))
	assert.NotEmpty(t, qs.Get("context"))
}

func TestAuthoriationRedirectsWithMultipleScopes(t *testing.T) {
	infra.InitializeApp()
	server := httptest.NewServer(routes.AuthorizationRouter())
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize", nil)
	q := req.URL.Query()
	q.Add("client_id", test.TestClient.ID)
	q.Add("grant_type", "authorization_code")
	q.Add("redirect_uri", test.TestClient.AllowedRedirectUrls[0])
	q.Add("scope", "profile contacts")
	q.Add("state", "client-data")

	req.URL.RawQuery = q.Encode()

	resp, _ := httpClient().Do(req)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs := url.Query()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/oauth2/authorize", url.Path)
	assert.Equal(t, "test-id", qs.Get("client_id"))
	assert.Equal(t, "profile contacts", qs.Get("requested_scopes"))
	assert.NotEmpty(t, qs.Get("context"))
}

func httpClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
