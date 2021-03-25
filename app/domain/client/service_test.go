package client_test

import (
	"goauth-extension/app/domain/client"
	"goauth-extension/app/infra"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientWithUnsupportedResponseType(t *testing.T) {
	infra.LoadConfig()
	service := client.NewService(client.NewRepository())

	err := service.Save(client.Client{
		AllowedResponseTypes: []string{"implicit"},
	})
	assert.NotNil(t, err)
}

func TestClientWithoutRedirectURLs(t *testing.T) {
	infra.LoadConfig()
	service := client.NewService(client.NewRepository())

	err := service.Save(client.Client{
		AllowedResponseTypes: []string{"code"},
		AllowedRedirectUrls:  []string{},
	})
	assert.NotNil(t, err)
}

func TestClientWithEmptyStringAsUrl(t *testing.T) {
	infra.LoadConfig()
	service := client.NewService(client.NewRepository())

	err := service.Save(client.Client{
		ID:                   "client-id",
		AllowedScopes:        []string{"profile"},
		AllowedResponseTypes: []string{"code"},
		AllowedRedirectUrls:  []string{""},
	})
	assert.NotNil(t, err)
}

func TestClientWithInvalidRedirectURLs(t *testing.T) {
	service := client.NewService(client.NewRepository())

	err := service.Save(client.Client{
		AllowedResponseTypes: []string{"code"},
		AllowedRedirectUrls:  []string{"https://not an url"},
	})
	assert.NotNil(t, err)
}

func TestClientWithoutScopes(t *testing.T) {
	service := client.NewService(client.NewRepository())

	err := service.Save(client.Client{
		AllowedResponseTypes: []string{"authorization_code"},
		AllowedRedirectUrls:  []string{"https://my-app.com"},
		AllowedScopes:        []string{},
	})
	assert.NotNil(t, err)
}

func TestClientSuccess(t *testing.T) {
	infra.LoadConfig()
	service := client.NewService(client.NewRepository())

	err := service.Save(client.Client{
		ID:                   "client-id",
		AllowedResponseTypes: []string{"code"},
		AllowedRedirectUrls:  []string{"https://my-app.com"},
		AllowedScopes:        []string{"profile"},
		RawSecret:            "visit my project github.com/giovaneliberato/opass",
	})

	assert.Nil(t, err)

	client := service.GetByID("client-id")
	assert.Equal(t, "client-id", client.ID)
	assert.Empty(t, client.RawSecret)
	assert.NotEmpty(t, client.HashedSecret)
}
