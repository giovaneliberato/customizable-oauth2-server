package authorization_test

import (
	"goauth-extension/app/domain"
	"goauth-extension/app/domain/authorization"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidClient(t *testing.T) {
	client := BuildTestClient()
	req := authorization.AuthorizationRequest{
		ClientID: "non-existent-client",
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.Equal(t, "invalid_request", err.Error)
	assert.Equal(t, "Invalid client", err.ErrorDescription)
}

func TestRedirectUrl(t *testing.T) {
	client := BuildTestClient()
	req := authorization.AuthorizationRequest{
		ClientID:    "test-id",
		RedirectURI: "https://malicious.domain/oauth-callback",
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.Equal(t, "invalid_request", err.Error)
	assert.Equal(t, "Invalid client details", err.ErrorDescription)
}

func TestUnsupportedGrantType(t *testing.T) {
	client := BuildTestClient()
	req := authorization.AuthorizationRequest{
		ClientID:    "test-id",
		RedirectURI: "https://test.client/oauth2-callback",
		GrantType:   "implicit",
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.Equal(t, "unauthorized_client", err.Error)
	assert.Equal(t, "Unsupported grant type", err.ErrorDescription)
}

func TestUnsupportedScopeNoneMatch(t *testing.T) {
	client := BuildTestClient()
	req := authorization.AuthorizationRequest{
		ClientID:    "test-id",
		RedirectURI: "https://test.client/oauth2-callback",
		GrantType:   "authorization_code",
		Scope:       []string{"admin-password"},
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.Equal(t, "invalid_scope", err.Error)
	assert.Equal(t, "Requested scopes are not valid", err.ErrorDescription)
}

func TestUnsupportedScopeOneMatch(t *testing.T) {
	client := BuildTestClient()
	req := authorization.AuthorizationRequest{
		ClientID:    "test-id",
		RedirectURI: "https://test.client/oauth2-callback",
		GrantType:   "authorization_code",
		Scope:       []string{"profile", "admin-password"},
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.Equal(t, "invalid_scope", err.Error)
	assert.Equal(t, "Requested scopes are not valid", err.ErrorDescription)
}

func TestSupportedScopeOneMatch(t *testing.T) {
	client := BuildTestClient()
	req := authorization.AuthorizationRequest{
		ClientID:    "test-id",
		RedirectURI: "https://test.client/oauth2-callback",
		GrantType:   "authorization_code",
		Scope:       []string{"profile"},
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.True(t, err.Empty())
}

func TestSupportedScopeAllMatch(t *testing.T) {
	client := BuildTestClient()
	req := authorization.AuthorizationRequest{
		ClientID:    "test-id",
		RedirectURI: "https://test.client/oauth2-callback",
		GrantType:   "authorization_code",
		Scope:       []string{"profile", "orders", "messages"},
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.True(t, err.Empty())
}

func BuildTestClient() domain.Client {
	return domain.Client{
		ID:                  "test-id",
		Secret:              "secret",
		AllowedRedirectUrls: []string{"https://test.client/oauth2-callback"},
		AllowedGrantTypes:   []string{"authorization_code"},
		AllowedScopes:       []string{"profile", "orders", "messages"},
	}
}
