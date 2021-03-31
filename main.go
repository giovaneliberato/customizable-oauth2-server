package main

import (
	"net/http"
	"oauth2-server/app"
	"oauth2-server/infra"

	"github.com/go-chi/chi"
	"github.com/go-chi/httplog"
)

func main() {
	appRouter := chi.NewRouter()
	managementRouter := chi.NewRouter()

	appRouter.Use(httplog.RequestLogger(infra.LOGGER))
	managementRouter.Use(httplog.RequestLogger(infra.LOGGER))

	app.InitApplication()
	app.ConfigApplicationRoutes(appRouter)
	app.ConfigManagementRoutes(managementRouter)

	http.ListenAndServe(":8080", appRouter)
	http.ListenAndServe(":8081", managementRouter)
}
