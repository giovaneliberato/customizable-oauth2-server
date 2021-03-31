package routes_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"oauth2-server/app/routes"
	"oauth2-server/domain"
	"oauth2-server/domain/context"
	"oauth2-server/test"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidRequest(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize", nil)
	req.URL.RawQuery = buildQueryStringWith("client_id", "").Encode()

	resp, _ := httpClient().Do(req)
	var respBody domain.OAuthError
	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Equal(t, "invalid_request", respBody.Err)
}

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
	qs := url.Values{}
	qs.Add("approved", "true")
	qs.Add("authorization_code", "3CJu2J5Yix8tQw")
	qs.Add("signed_context", generateValidSignedContext()+"tampered")

	req, _ := http.NewRequest("GET", server.URL+"/oauth2/approve-authorization", nil)
	req.URL.RawQuery = qs.Encode()

	resp, _ := httpClient().Do(req)

	var respBody domain.OAuthError
	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Equal(t, "invalid_request", respBody.Err)
}

func TestUnnaprovedAuthorization(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	qs := url.Values{}
	qs.Add("approved", "false")
	qs.Add("authorization_code", "3CJu2J5Yix8tQw")
	qs.Add("signed_context", generateValidSignedContext())

	req, _ := http.NewRequest("GET", server.URL+"/oauth2/approve-authorization", nil)
	req.URL.RawQuery = qs.Encode()
	resp, _ := httpClient().Do(req)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs = url.Query()

	assert.Equal(t, test.TestClient.AllowedRedirectUrls[0], strings.Split(url.String(), "?")[0])
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "access_denied", qs.Get("error"))
	assert.Equal(t, "state", qs.Get("state"))
}

func TestApproveAuthorizationInvalidRequest(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	qs := url.Values{}

	req, _ := http.NewRequest("GET", server.URL+"/oauth2/approve-authorization", nil)
	req.URL.RawQuery = qs.Encode()
	resp, _ := httpClient().Do(req)

	var respBody domain.OAuthError
	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Equal(t, "invalid_request", respBody.Err)
}

func TestSuccessfulAuthorizationRedirectsResponseTypeToken(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)

	signer := context.NewContextSigner()
	context := context.Context{
		ClientID:     test.TestClient.ID,
		State:        "state",
		ResponseType: []string{"token"},
		Scope:        []string{"profile"},
		RedirectURI:  test.TestClient.AllowedRedirectUrls[0],
	}
	signedContext, _ := signer.SignAndEncode(context)

	qs := url.Values{}
	qs.Add("approved", "true")
	qs.Add("authorization_code", "3CJu2J5Yix8tQw")
	qs.Add("signed_context", signedContext)

	req, _ := http.NewRequest("GET", server.URL+"/oauth2/approve-authorization", nil)
	req.URL.RawQuery = qs.Encode()
	resp, _ := httpClient().Do(req)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs = url.Query()

	assert.Equal(t, test.TestClient.AllowedRedirectUrls[0], strings.Split(url.String(), "?")[0])
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "state", qs.Get("state"))
	assert.Empty(t, qs.Get("code"))
	assert.NotEmpty(t, qs.Get("access_token"))
	assert.NotEmpty(t, qs.Get("refresh_token"))
}

func TestSuccessfulAuthorizationRedirectsResponseTypeHybrid(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)

	signer := context.NewContextSigner()
	context := context.Context{
		ClientID:     test.TestClient.ID,
		State:        "state",
		ResponseType: []string{"token", "code"},
		Scope:        []string{"profile"},
		RedirectURI:  test.TestClient.AllowedRedirectUrls[0],
	}
	signedContext, _ := signer.SignAndEncode(context)

	qs := url.Values{}
	qs.Add("approved", "true")
	qs.Add("authorization_code", "3CJu2J5Yix8tQw")
	qs.Add("signed_context", signedContext)

	req, _ := http.NewRequest("GET", server.URL+"/oauth2/approve-authorization", nil)
	req.URL.RawQuery = qs.Encode()
	resp, _ := httpClient().Do(req)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs = url.Query()

	assert.Equal(t, test.TestClient.AllowedRedirectUrls[0], strings.Split(url.String(), "?")[0])
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "state", qs.Get("state"))
	assert.NotEmpty(t, qs.Get("code"))
	assert.NotEmpty(t, qs.Get("access_token"))
	assert.NotEmpty(t, qs.Get("refresh_token"))
}

func TestSuccessfulAuthorizationRedirectsClient(t *testing.T) {
	var server = test.TestServerFor(routes.AuthorizationRouter)
	qs := url.Values{}
	qs.Add("approved", "true")
	qs.Add("authorization_code", "3CJu2J5Yix8tQw")
	qs.Add("signed_context", generateValidSignedContext())

	req, _ := http.NewRequest("GET", server.URL+"/oauth2/approve-authorization", nil)
	req.URL.RawQuery = qs.Encode()
	resp, _ := httpClient().Do(req)

	redirectURL := resp.Header.Get("Location")
	url, _ := url.Parse(redirectURL)
	qs = url.Query()

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
	signer := context.NewContextSigner()
	Context := context.Context{
		ClientID:     test.TestClient.ID,
		State:        "state",
		ResponseType: []string{"code"},
		Scope:        []string{"profile"},
		RedirectURI:  test.TestClient.AllowedRedirectUrls[0],
	}
	signedContext, _ := signer.SignAndEncode(Context)
	return signedContext
}
