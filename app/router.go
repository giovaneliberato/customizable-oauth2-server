package app

import (
	"oauth2-server/app/routes"

	"github.com/go-chi/chi"
)

var applicationRoutes = []func(*chi.Mux){
	routes.AuthorizationRouter,
	routes.TokenRouter,
}

var managementRoutes = []func(*chi.Mux){
	routes.ClienRouter,
}

func ConfigApplicationRoutes(r *chi.Mux) {
	configureRoutes(r, applicationRoutes)
}

func ConfigManagementRoutes(r *chi.Mux) {
	configureRoutes(r, managementRoutes)
}

func configureRoutes(r *chi.Mux, fns []func(*chi.Mux)) {
	for _, routeFn := range fns {
		routeFn(r)
	}
}
