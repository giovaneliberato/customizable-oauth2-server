package authorization_test

import (
	"oauth2-server/domain/authorization"
	"oauth2-server/domain/client"
	"oauth2-server/test"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidClient(t *testing.T) {
	auth := authorization.Authorization{
		ClientID: "some-client",
	}

	err := authorization.Validate(client.Client{}, auth)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.True(t, err.Abort)
	assert.Equal(t, "invalid_request", err.Err)
	assert.Equal(t, "Invalid client details", err.ErrorDescription)
}

func TestInvalidClientID(t *testing.T) {
	client := test.TestClient
	auth := authorization.Authorization{
		ClientID: "non-existent-client",
	}

	err := authorization.Validate(client, auth)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.True(t, err.Abort)
	assert.Equal(t, "invalid_request", err.Err)
	assert.Equal(t, "Invalid client details", err.ErrorDescription)
}

func TestRedirectUrl(t *testing.T) {
	client := test.TestClient
	auth := authorization.Authorization{
		ClientID:    "test-id",
		RedirectURI: "https://malicious.domain/oauth-callback",
	}

	err := authorization.Validate(client, auth)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.True(t, err.Abort)
	assert.Equal(t, "invalid_request", err.Err)
	assert.Equal(t, "Invalid client details", err.ErrorDescription)
}

func TestUnsupportedResponseType(t *testing.T) {
	client := test.TestClient
	auth := authorization.Authorization{
		ClientID:     client.ID,
		RedirectURI:  client.AllowedRedirectUrls[0],
		ResponseType: []string{"implicit"},
	}

	err := authorization.Validate(client, auth)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.False(t, err.Abort)
	assert.Equal(t, "unsupported_response_type", err.Err)
	assert.Equal(t, "Unsupported response type", err.ErrorDescription)
}

func TestUnsupportedScopeNoneMatch(t *testing.T) {
	client := test.TestClient
	auth := authorization.Authorization{
		ClientID:     client.ID,
		RedirectURI:  client.AllowedRedirectUrls[0],
		ResponseType: []string{"code"},
		Scope:        []string{"admin-password"},
	}

	err := authorization.Validate(client, auth)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.False(t, err.Abort)
	assert.Equal(t, "invalid_scope", err.Err)
	assert.Equal(t, "Requested scopes are not valid", err.ErrorDescription)
}

func TestUnsupportedScopeOneMatch(t *testing.T) {
	client := test.TestClient
	auth := authorization.Authorization{
		ClientID:     "test-id",
		RedirectURI:  "https://test.client/oauth2-callback",
		ResponseType: []string{"code"},
		Scope:        []string{"profile", "admin-password"},
	}

	err := authorization.Validate(client, auth)
	assert.NotNil(t, err)
	assert.False(t, err.Empty())
	assert.False(t, err.Abort)
	assert.Equal(t, "invalid_scope", err.Err)
	assert.Equal(t, "Requested scopes are not valid", err.ErrorDescription)
}

func TestSupportedScopeOneMatch(t *testing.T) {
	client := test.TestClient
	auth := authorization.Authorization{
		ClientID:     client.ID,
		RedirectURI:  client.AllowedRedirectUrls[0],
		ResponseType: []string{"code"},
		Scope:        []string{"profile"},
	}

	err := authorization.Validate(client, auth)
	assert.Nil(t, err)
}

func TestSupportedScopeTwoMatch(t *testing.T) {
	client := test.TestClient
	auth := authorization.Authorization{
		ClientID:     client.ID,
		RedirectURI:  client.AllowedRedirectUrls[0],
		ResponseType: []string{"code"},
		Scope:        []string{"profile", "messages"},
	}

	err := authorization.Validate(client, auth)
	assert.Nil(t, err)
}

func TestSupportedScopeAllMatch(t *testing.T) {
	client := test.TestClient
	auth := authorization.Authorization{
		ClientID:     client.ID,
		RedirectURI:  client.AllowedRedirectUrls[0],
		ResponseType: []string{"code"},
		Scope:        []string{"profile", "contacts", "messages"},
	}

	err := authorization.Validate(client, auth)
	assert.Nil(t, err)
}
