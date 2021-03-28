package infra

import (
	"oauth2-server/cmd/domain/authorization"
	"oauth2-server/cmd/domain/client"
	"oauth2-server/cmd/domain/token"
	"oauth2-server/cmd/routes"

	"github.com/golobby/container/v2"
)

var componentProviders = []interface{}{
	authorization.NewContextSigner,
	client.NewRepository,
	client.NewService,
	authorization.NewService,
	token.NewExternalServiceClient,
	token.NewService,
	routes.NewTokenRoutes,
	routes.NewAuthorizationRoutes,
	routes.NewClientRoutes,
}

func InitializeComponents() {
	for _, provider := range componentProviders {
		container.Singleton(provider)
	}
}

func InitApplication() {
	LoadConfig()
	InitializeComponents()
}
