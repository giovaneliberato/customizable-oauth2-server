package routes

import (
	"encoding/json"
	"net/http"
	"oauth2-server/domain/client"

	"github.com/go-chi/chi"
	"github.com/golobby/container/v2"
)

func ClienRouter(r *chi.Mux) {

	var route ClientRoutes
	container.Make(&route)

	r.Post("/oauth2/client", route.Create)
}

type ClientRoutes interface {
	Create(http.ResponseWriter, *http.Request)
}

type clientRoutes struct {
	service client.Service
}

func NewClientRoutes(service client.Service) ClientRoutes {
	return &clientRoutes{
		service: service,
	}
}

func (c *clientRoutes) Create(w http.ResponseWriter, r *http.Request) {
	client := client.Client{}
	err := json.NewDecoder(r.Body).Decode(&client)

	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	err = c.service.Save(client)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
