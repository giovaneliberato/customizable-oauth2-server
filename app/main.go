package main

import (
	"goauth-extension/app/infra"
	"goauth-extension/app/routes"
	"net/http"
)

func main() {
	infra.InitializeComponents()
	http.ListenAndServe(":3000", routes.AuthorizationRoutes())
}
