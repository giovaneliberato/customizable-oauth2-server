package app

import (
	"oauth2-server/app/routes"
	"oauth2-server/domain/authorization"
	"oauth2-server/domain/client"
	"oauth2-server/domain/context"
	"oauth2-server/domain/token"
	"oauth2-server/infra"

	"github.com/golobby/container/v2"
)

var componentProviders = []interface{}{
	context.NewContextSigner,
	client.NewRepository,
	client.NewService,
	authorization.NewService,
	infra.NewExternalServiceClient,
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
