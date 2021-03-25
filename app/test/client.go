package test

import (
	"goauth-extension/app/domain/client"

	"github.com/stretchr/testify/mock"
)

type ClientServiceMock struct {
	mock.Mock
	Return client.Client
}

func (m *ClientServiceMock) GetByID(ID string) client.Client {
	return m.Return
}

func (m *ClientServiceMock) Save(client.Client) error {
	return nil
}

func (m *ClientServiceMock) ValidateSecret(c client.Client, secret string) error {
	return nil
}

var TestClient = client.Client{
	ID:                   "test-id",
	RawSecret:            "secret",
	HashedSecret:         client.HashSecret("secret"),
	AllowedRedirectUrls:  []string{"https://test.client/oauth2-callback"},
	AllowedResponseTypes: []string{"code"},
	AllowedScopes:        []string{"profile", "contacts", "messages"},
}
