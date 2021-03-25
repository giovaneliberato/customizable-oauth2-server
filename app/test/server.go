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
	"github.com/spf13/viper"
)

func ConfigureTestScenario() {
	infra.InitializeComponents()
	loadTestConfigFile()

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

func loadTestConfigFile() {
	viper.AddConfigPath(rootDir() + "/test")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
}

func rootDir() string {
	_, b, _, _ := runtime.Caller(0)
	d := path.Join(path.Dir(b))
	return filepath.Dir(d)
}
