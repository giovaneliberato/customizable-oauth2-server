package infra

import (
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/client"
	"goauth-extension/app/domain/token"
	"goauth-extension/app/routes"

	"github.com/golobby/container/v2"
)

var componentProviders = []interface{}{
	// domain
	token.NewTokenSigner,
	client.NewRepository,
	client.NewService,
	authorization.NewService,

	//routes
	routes.NewAuthorizationRoutes,
	routes.NewClientRoutes,
}

func InitializeComponents() {
	for _, component := range componentProviders {
		container.Singleton(component)
	}
}

func InitApplication() {
	LoadConfig()
	InitializeComponents()
}
