package client_test

import (
	"goauth-extension/app/domain/client"
	"goauth-extension/app/infra"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientWithUnsupportedGrantType(t *testing.T) {
	service := client.NewService(client.NewRepository())

	err := service.Save(&client.Client{
		AllowedGrantTypes: []string{"implicit"},
	})
	assert.NotNil(t, err)
}

func TestClientWithoutRedirectURLs(t *testing.T) {
	service := client.NewService(client.NewRepository())

	err := service.Save(&client.Client{
		AllowedGrantTypes:   []string{"authorization_code"},
		AllowedRedirectUrls: []string{},
	})
	assert.NotNil(t, err)
}

func TestClientWithoutScopes(t *testing.T) {
	service := client.NewService(client.NewRepository())

	err := service.Save(&client.Client{
		AllowedGrantTypes:   []string{"authorization_code"},
		AllowedRedirectUrls: []string{"https://my-app.com"},
		AllowedScopes:       []string{},
	})
	assert.NotNil(t, err)
}

func TestClientSuccess(t *testing.T) {
	infra.LoadConfig()
	service := client.NewService(client.NewRepository())

	err := service.Save(&client.Client{
		ID:                  "client-id",
		AllowedGrantTypes:   []string{"code"},
		AllowedRedirectUrls: []string{"https://my-app.com"},
		AllowedScopes:       []string{"profile"},
		RawSecret:           "visit my project github.com/giovaneliberato/opass",
	})

	assert.Nil(t, err)

	client := service.GetByID("client-id")
	assert.Equal(t, "client-id", client.ID)
	assert.Empty(t, client.RawSecret)
	assert.NotEmpty(t, client.HashedSecret)
}
