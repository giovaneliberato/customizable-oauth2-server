package infra

import (
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/client"
	"goauth-extension/app/domain/token"
	"goauth-extension/app/routes"

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
