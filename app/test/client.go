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

var TestClient = client.Client{
	ID:                  "test-id",
	RawSecret:           "secret",
	AllowedRedirectUrls: []string{"https://test.client/oauth2-callback"},
	AllowedGrantTypes:   []string{"code"},
	AllowedScopes:       []string{"profile", "contacts", "messages"},
}
