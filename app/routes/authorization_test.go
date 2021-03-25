package routes_test

import (
	"encoding/json"
	"goauth-extension/app/domain"
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/routes"
	"goauth-extension/app/test"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidClientID(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize", nil)
	req.URL.RawQuery = buildQueryStringWith("client_id", "invalid").Encode()

	resp, _ := httpClient().Do(req)
	var respBody domain.OAuthError

	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Equal(t, "invalid_request", respBody.Err)
}

func TestInvalidRedirectURL(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize", nil)
	req.URL.RawQuery = buildQueryStringWith("redirect_uri", "not even a url").Encode()

	resp, _ := httpClient().Do(req)
	var respBody domain.OAuthError

	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Equal(t, "invalid_request", respBody.Err)
}

func TestUnsupportedGrantType(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize", nil)
	req.URL.RawQuery = buildQueryStringWith("response_type", "invalid_grant").Encode()

	resp, _ := httpClient().Do(req)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs := url.Query()

	assert.Equal(t, test.TestClient.AllowedRedirectUrls[0], strings.Split(url.String(), "?")[0])
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "unsupported_response_type", qs.Get("error"))
	assert.Equal(t, "client-data", qs.Get("state"))
}

func TestInvalidScope(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize", nil)
	req.URL.RawQuery = buildQueryStringWith("scope", "everythingggggg").Encode()

	resp, _ := httpClient().Do(req)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs := url.Query()

	assert.Equal(t, test.TestClient.AllowedRedirectUrls[0], strings.Split(url.String(), "?")[0])
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "invalid_scope", qs.Get("error"))
	assert.Equal(t, "client-data", qs.Get("state"))
}

func TestAuthoriationRedirectsToApproval(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize", nil)
	req.URL.RawQuery = buildQueryStringWith("scope", "profile").Encode()

	resp, _ := httpClient().Do(req)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs := url.Query()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/oauth2/authorize", url.Path)
	assert.Equal(t, "test-id", qs.Get("client_id"))
	assert.Equal(t, "profile", qs.Get("requested_scopes"))
	assert.NotEmpty(t, qs.Get("signed_context"))
}

func TestAuthoriationRedirectsToApprovalWithMultipleScopes(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize", nil)
	req.URL.RawQuery = buildQueryStringWith("scope", "profile contacts").Encode()

	resp, _ := httpClient().Do(req)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs := url.Query()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/oauth2/authorize", url.Path)
	assert.Equal(t, test.TestClient.ID, qs.Get("client_id"))
	assert.Equal(t, "profile contacts", qs.Get("requested_scopes"))
	assert.NotEmpty(t, qs.Get("signed_context"))
}

func TestUnsuccessfulAuthorization(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	req, _ := http.NewRequest("POST", server.URL+"/oauth2/approve-authorization", nil)
	req.PostForm = make(url.Values)
	req.PostForm.Add("approved", "true")
	req.PostForm.Add("authorization_code", "3CJu2J5Yix8tQw")
	req.PostForm.Add("signed_context", generateValidSignedContext()+"tampered")

	resp, _ := httpClient().Do(req)
	var respBody domain.OAuthError

	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Equal(t, "invalid_request", respBody.Err)
}

func TestUnnaprovedAuthorization(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	form := url.Values{}
	form.Add("approved", "false")
	form.Add("authorization_code", "3CJu2J5Yix8tQw")
	form.Add("signed_context", generateValidSignedContext())
	resp, _ := httpClient().PostForm(server.URL+"/oauth2/approve-authorization", form)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs := url.Query()

	assert.Equal(t, test.TestClient.AllowedRedirectUrls[0], strings.Split(url.String(), "?")[0])
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "access_denied", qs.Get("error"))
	assert.Equal(t, "state", qs.Get("state"))
}

func TestSuccessfulAuthorizationRedirectsClient(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	form := url.Values{}
	form.Add("approved", "true")
	form.Add("authorization_code", "3CJu2J5Yix8tQw")
	form.Add("signed_context", generateValidSignedContext())
	resp, _ := httpClient().PostForm(server.URL+"/oauth2/approve-authorization", form)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs := url.Query()

	assert.Equal(t, test.TestClient.AllowedRedirectUrls[0], strings.Split(url.String(), "?")[0])
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "state", qs.Get("state"))
	assert.NotEmpty(t, qs.Get("code"))
}

func buildQueryStringWith(overrideKey string, value string) url.Values {
	q := buildQueryString()
	q.Set(overrideKey, value)
	return q
}

func buildQueryString() url.Values {
	q := url.Values{}
	q.Add("client_id", test.TestClient.ID)
	q.Add("response_type", "code")
	q.Add("redirect_uri", test.TestClient.AllowedRedirectUrls[0])
	q.Add("scope", "profile")
	q.Add("state", "client-data")

	return q
}

func httpClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func generateValidSignedContext() string {
	signer := authorization.NewContextSigner()
	Context := authorization.Context{
		ClientID:    test.TestClient.ID,
		State:       "state",
		Scope:       []string{"profile"},
		RedirectURI: test.TestClient.AllowedRedirectUrls[0],
	}
	signedContext, _ := signer.SignAndEncode(Context)
	return signedContext
}
