package authorization_test

import (
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/client"
	"goauth-extension/app/test"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidClient(t *testing.T) {
	req := authorization.AuthorizationRequest{
		ClientID: "some-client",
	}

	err := authorization.Validate(client.Client{}, req)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.True(t, err.Abort)
	assert.Equal(t, "invalid_request", err.Err)
	assert.Equal(t, "Invalid client details", err.ErrorDescription)
}

func TestInvalidClientID(t *testing.T) {
	client := test.TestClient
	req := authorization.AuthorizationRequest{
		ClientID: "non-existent-client",
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.True(t, err.Abort)
	assert.Equal(t, "invalid_request", err.Err)
	assert.Equal(t, "Invalid client details", err.ErrorDescription)
}

func TestRedirectUrl(t *testing.T) {
	client := test.TestClient
	req := authorization.AuthorizationRequest{
		ClientID:    "test-id",
		RedirectURI: "https://malicious.domain/oauth-callback",
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.True(t, err.Abort)
	assert.Equal(t, "invalid_request", err.Err)
	assert.Equal(t, "Invalid client details", err.ErrorDescription)
}

func TestUnsupportedGrantType(t *testing.T) {
	client := test.TestClient
	req := authorization.AuthorizationRequest{
		ClientID:    client.ID,
		RedirectURI: client.AllowedRedirectUrls[0],
		GrantType:   "implicit",
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.False(t, err.Abort)
	assert.Equal(t, "unsupported_response_type", err.Err)
	assert.Equal(t, "Unsupported grant type", err.ErrorDescription)
}

func TestUnsupportedScopeNoneMatch(t *testing.T) {
	client := test.TestClient
	req := authorization.AuthorizationRequest{
		ClientID:    client.ID,
		RedirectURI: client.AllowedRedirectUrls[0],
		GrantType:   "code",
		Scope:       []string{"admin-password"},
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.False(t, err.Abort)
	assert.Equal(t, "invalid_scope", err.Err)
	assert.Equal(t, "Requested scopes are not valid", err.ErrorDescription)
}

func TestUnsupportedScopeOneMatch(t *testing.T) {
	client := test.TestClient
	req := authorization.AuthorizationRequest{
		ClientID:    "test-id",
		RedirectURI: "https://test.client/oauth2-callback",
		GrantType:   "authorization_code",
		Scope:       []string{"profile", "admin-password"},
	}

	err := authorization.Validate(client, req)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.False(t, err.Abort)
	assert.Equal(t, "invalid_scope", err.Err)
	assert.Equal(t, "Requested scopes are not valid", err.ErrorDescription)
}

func TestSupportedScopeOneMatch(t *testing.T) {
	client := test.TestClient
	req := authorization.AuthorizationRequest{
		ClientID:    client.ID,
		RedirectURI: client.AllowedRedirectUrls[0],
		GrantType:   "code",
		Scope:       []string{"profile"},
	}

	err := authorization.Validate(client, req)
	assert.Nil(t, err)
}

func TestSupportedScopeTwoMatch(t *testing.T) {
	client := test.TestClient
	req := authorization.AuthorizationRequest{
		ClientID:    client.ID,
		RedirectURI: client.AllowedRedirectUrls[0],
		GrantType:   "code",
		Scope:       []string{"profile", "messages"},
	}

	err := authorization.Validate(client, req)
	assert.Nil(t, err)
}

func TestSupportedScopeAllMatch(t *testing.T) {
	client := test.TestClient
	req := authorization.AuthorizationRequest{
		ClientID:    client.ID,
		RedirectURI: client.AllowedRedirectUrls[0],
		GrantType:   "code",
		Scope:       []string{"profile", "contacts", "messages"},
	}

	err := authorization.Validate(client, req)
	assert.Nil(t, err)
}
