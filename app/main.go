package main

import (
	"net/http"
	"oauth2-server/app/infra"

	"github.com/go-chi/chi"
)

func main() {
	appRouter := chi.NewRouter()
	managementRouter := chi.NewRouter()

	infra.InitApplication()
	infra.ConfigApplicationRoutes(appRouter)
	infra.ConfigManagementRoutes(managementRouter)

	http.ListenAndServe(":8080", appRouter)
	http.ListenAndServe(":8081", managementRouter)
}
