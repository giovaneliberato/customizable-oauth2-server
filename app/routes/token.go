package routes

import (
	"encoding/json"
	"goauth-extension/app/domain/token"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/golobby/container/v2"
)

func TokenRouter(r *chi.Mux) {
	var route TokenRoutes
	container.Make(&route)

	r.Post("/oauth2/token", route.Exchange)
}

type TokenRoutes interface {
	Exchange(http.ResponseWriter, *http.Request)
}

type tokenRoutes struct {
	service token.Service
}

func NewTokenRoutes(service token.Service) TokenRoutes {
	return &tokenRoutes{
		service: service,
	}
}

func (t *tokenRoutes) Exchange(w http.ResponseWriter, r *http.Request) {
	authCodeRequest := parseAuthorizationCodeRequest(r)
	accessToken, err := t.service.Exchange(authCodeRequest)

	if err != nil {
		renderError(w, r, err)
		return
	}

	jsonBody, _ := json.Marshal(accessToken)
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBody)
}

func parseAuthorizationCodeRequest(r *http.Request) token.AuthorizationCodeRequest {
	return token.AuthorizationCodeRequest{
		ClientID:                r.FormValue("client_id"),
		ClientSecret:            r.FormValue("client_secret"),
		GrantType:               r.FormValue("grant_type"),
		SignedAuthorizationCode: r.FormValue("code"),
	}
}
