package app

import (
	"oauth2-server/app/routes"
	"oauth2-server/domain/authorization"
	"oauth2-server/domain/client"
	"oauth2-server/domain/context"
	"oauth2-server/domain/token"

	"github.com/golobby/container/v2"
)

var componentProviders = []interface{}{
	context.NewContextSigner,
	client.NewRepository,
	client.NewService,
	token.NewExternalServiceClient,
	token.NewService,
	authorization.NewService,
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
