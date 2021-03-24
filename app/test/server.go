package test

import (
	"goauth-extension/app/domain/client"
	"goauth-extension/app/infra"
	"net/http/httptest"

	"github.com/go-chi/chi"
	"github.com/golobby/container/v2"
)

func ConfigureTestScenario() {
	infra.InitApplication()

	var repository client.Repository
	container.Make(&repository)

	repository.Save(TestClient)
}

func TestServerFor(routes ...func(*chi.Mux)) *httptest.Server {
	ConfigureTestScenario()
	router := chi.NewMux()
	server := httptest.NewServer(router)
	for _, route := range routes {
		route(router)
	}

	return server
}
