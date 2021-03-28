package main

import (
	"net/http"
	"oauth2-server/app"

	"github.com/go-chi/chi"
)

func main() {
	appRouter := chi.NewRouter()
	managementRouter := chi.NewRouter()

	app.InitApplication()
	app.ConfigApplicationRoutes(appRouter)
	app.ConfigManagementRoutes(managementRouter)

	http.ListenAndServe(":8080", appRouter)
	http.ListenAndServe(":8081", managementRouter)
}
