package main

import (
	"goauth-extension/app/routes"
	"net/http"
)

func main() {
	http.ListenAndServe(":3000", routes.AuthorizationRoutes())
}
