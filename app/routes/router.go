package routes

import "github.com/go-chi/chi"

var applicationRoutes = []func(*chi.Mux){
	AuthorizationRouter,
	TokenRouter,
}

var managementRoutes = []func(*chi.Mux){
	ClienRouter,
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
