package routes_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"oauth2-server/app/routes"
	"oauth2-server/domain"
	"oauth2-server/domain/context"
	"oauth2-server/domain/token"
	"oauth2-server/test"
	"testing"

	"github.com/golobby/container/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAccessTokenExchangeInvalidRequest(t *testing.T) {
	var server = test.TestServerFor(routes.TokenRouter)

	form := url.Values{}
	form.Add("client_id", test.TestClient.ID)
	form.Add("client_secret", test.TestClient.RawSecret)
	form.Add("code", "")
	form.Add("grant_type", "authorization_code")

	resp, _ := httpClient().PostForm(server.URL+"/oauth2/token", form)

	var respBody domain.OAuthError
	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.NotEmpty(t, respBody.Err)
}

func TestAccessTokenExchangeFailure(t *testing.T) {
	var server = test.TestServerFor(routes.TokenRouter)

	ctx := context.Context{
		ClientID:          test.TestClient.ID,
		ResponseType:      []string{"code"},
		Scope:             test.TestClient.AllowedScopes,
		RedirectURI:       test.TestClient.AllowedRedirectUrls[0],
		AuthorizationCode: "some-authorization-code",
	}

	signedAuthCode, _ := getContextSigner().SignAndEncode(ctx)

	form := url.Values{}
	form.Add("client_id", test.TestClient.ID)
	form.Add("client_secret", test.TestClient.RawSecret)
	form.Add("code", signedAuthCode+"tampered")
	form.Add("grant_type", "authorization_code")

	resp, _ := httpClient().PostForm(server.URL+"/oauth2/token", form)

	var respBody domain.OAuthError
	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.NotEmpty(t, respBody.Err)
}

func TestAccessTokenExchangeSuccess(t *testing.T) {
	var server = test.TestServerFor(routes.TokenRouter)

	ctx := context.Context{
		ClientID:          test.TestClient.ID,
		ResponseType:      []string{"code"},
		Scope:             test.TestClient.AllowedScopes,
		RedirectURI:       test.TestClient.AllowedRedirectUrls[0],
		AuthorizationCode: "some-authorization-code",
	}

	signedAuthCode, _ := getContextSigner().SignAndEncode(ctx)

	form := url.Values{}
	form.Add("client_id", test.TestClient.ID)
	form.Add("client_secret", test.TestClient.RawSecret)
	form.Add("code", signedAuthCode)
	form.Add("grant_type", "authorization_code")

	resp, _ := httpClient().PostForm(server.URL+"/oauth2/token", form)

	var respBody token.AccessTokenResponse
	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "bearer", respBody.TokenType)
	assert.NotEmpty(t, respBody.AccessToken)
	assert.NotEmpty(t, respBody.RefreshToken)
}

func TestRefreshTokenInvalidRequest(t *testing.T) {
	var server = test.TestServerFor(routes.TokenRouter)

	form := url.Values{}
	form.Add("client_id", test.TestClient.ID)
	form.Add("client_secret", test.TestClient.RawSecret)
	form.Add("refresh_token", "")
	form.Add("grant_type", "refresh_token")

	resp, _ := httpClient().PostForm(server.URL+"/oauth2/token", form)

	var respBody domain.OAuthError
	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.NotEmpty(t, respBody.Err)
}

func TestRefreshAccessTokenExchangeSuccess(t *testing.T) {
	var server = test.TestServerFor(routes.TokenRouter)

	form := url.Values{}
	form.Add("client_id", test.TestClient.ID)
	form.Add("client_secret", test.TestClient.RawSecret)
	form.Add("refresh_token", uuid.NewString())
	form.Add("grant_type", "refresh_token")

	resp, _ := httpClient().PostForm(server.URL+"/oauth2/token", form)

	var respBody token.AccessTokenResponse
	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "bearer", respBody.TokenType)
	assert.NotEmpty(t, respBody.AccessToken)
	assert.NotEmpty(t, respBody.RefreshToken)
}

func TestRefreshAccessTokenExchangeWrongGrantType(t *testing.T) {
	var server = test.TestServerFor(routes.TokenRouter)

	form := url.Values{}
	form.Add("client_id", test.TestClient.ID)
	form.Add("client_secret", test.TestClient.RawSecret)
	form.Add("refresh_token", uuid.NewString())
	form.Add("grant_type", "code")

	resp, _ := httpClient().PostForm(server.URL+"/oauth2/token", form)

	var respBody domain.OAuthError
	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.NotEmpty(t, respBody.Err)
}

func TestRefreshAccessTokenExchangeWrongClientID(t *testing.T) {
	var server = test.TestServerFor(routes.TokenRouter)

	form := url.Values{}
	form.Add("client_id", "another-client-id")
	form.Add("client_secret", test.TestClient.RawSecret)
	form.Add("refresh_token", uuid.NewString())
	form.Add("grant_type", "code")

	resp, _ := httpClient().PostForm(server.URL+"/oauth2/token", form)

	var respBody domain.OAuthError
	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.NotEmpty(t, respBody.Err)
}

func TestRefreshAccessTokenExchangeWrongClientSecret(t *testing.T) {
	var server = test.TestServerFor(routes.TokenRouter)

	form := url.Values{}
	form.Add("client_id", test.TestClient.ID)
	form.Add("client_secret", "attempt 1/∞")
	form.Add("refresh_token", uuid.NewString())
	form.Add("grant_type", "code")

	resp, _ := httpClient().PostForm(server.URL+"/oauth2/token", form)

	var respBody domain.OAuthError
	json.NewDecoder(resp.Body).Decode(&respBody)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.NotEmpty(t, respBody.Err)
}

func getContextSigner() context.Signer {
	var contextSigner context.Signer
	container.Make(&contextSigner)
	return contextSigner
}
