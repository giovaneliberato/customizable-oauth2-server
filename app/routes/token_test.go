package routes_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"oauth2-server/app/domain"
	"oauth2-server/app/domain/authorization"
	"oauth2-server/app/domain/token"
	"oauth2-server/app/routes"
	"oauth2-server/app/test"
	"testing"

	"github.com/golobby/container/v2"
	"github.com/stretchr/testify/assert"
)

func TestAccessTokenExchangeFailure(t *testing.T) {
	var server = test.TestServerFor(routes.TokenRouter)

	ctx := authorization.Context{
		ClientID:          test.TestClient.ID,
		ResponseType:      "code",
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

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.NotEmpty(t, respBody.Err)
}

func TestAccessTokenExchangeSuccess(t *testing.T) {
	var server = test.TestServerFor(routes.TokenRouter)

	ctx := authorization.Context{
		ClientID:          test.TestClient.ID,
		ResponseType:      "code",
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

func getContextSigner() authorization.ContextSigner {
	var contextSigner authorization.ContextSigner
	container.Make(&contextSigner)
	return contextSigner
}
