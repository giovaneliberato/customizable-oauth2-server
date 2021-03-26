package test

import (
	"goauth-extension/app/domain/client"
	"goauth-extension/app/infra"
	"net/http/httptest"
	"path"
	"path/filepath"
	"runtime"

	"github.com/go-chi/chi"
	"github.com/golobby/container/v2"
)

func ConfigureTestScenario() {
	infra.LoadTestConfig()
	infra.InitializeComponents()

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

func rootDir() string {
	_, b, _, _ := runtime.Caller(0)
	d := path.Join(path.Dir(b))
	return filepath.Dir(d)
}
