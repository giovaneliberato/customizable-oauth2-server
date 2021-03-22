package infra

import (
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/client"

	"github.com/golobby/container/v2"
)

var componentProviders = []interface{}{
	client.NewService,
	authorization.NewService,
}

func InitializeComponents() {
	for _, component := range componentProviders {
		container.Singleton(component)
	}
}
