package main

import (
	"goauth-extension/app/infra"
	"goauth-extension/app/routes"
	"net/http"
)

func InitializeApp() {
}

func main() {
	infra.InitializeApp()
	http.ListenAndServe(":3000", routes.AuthorizationRoutes())
}
