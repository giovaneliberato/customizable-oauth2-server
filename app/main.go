package main

import (
	"goauth-extension/app/infra"
	"goauth-extension/app/routes"
	"net/http"

	"github.com/go-chi/chi"
)

func main() {
	infra.InitApplication()

	appRouter := chi.NewRouter()
	managementRouter := chi.NewRouter()

	routes.ConfigApplicationRoutes(appRouter)
	routes.ConfigManagementRoutes(managementRouter)

	http.ListenAndServe(":8080", appRouter)
	http.ListenAndServe(":8081", managementRouter)
}
