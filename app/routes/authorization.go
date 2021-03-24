package routes

import (
	"encoding/json"
	"goauth-extension/app/domain/authorization"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi"
	"github.com/golobby/container/v2"
)

// AuthorizationRoutes returns a chi.Router with all authorization routes mapped
func AuthorizationRouter() chi.Router {
	router := chi.NewRouter()

	var route AuthorizationRoutes
	container.Make(&route)

	router.Get("/oauth2/authorize", route.Authorize)
	router.Post("/oauth2/authorize-callback", route.ProcessAuthorization)

	return router
}

type AuthorizationRoutes interface {
	Authorize(http.ResponseWriter, *http.Request)
	ProcessAuthorization(http.ResponseWriter, *http.Request)
}

type routes struct {
	service authorization.Service
}

func NewAuthorizationRoutes(service authorization.Service) AuthorizationRoutes {
	return &routes{
		service: service,
	}
}

func (a *routes) Authorize(w http.ResponseWriter, r *http.Request) {
	authRequest := parse(r.URL.Query())

	context, err := a.service.Authorize(authRequest)

	if err != nil {
		jsonBody, _ := json.Marshal(err)
		http.Error(w, string(jsonBody), http.StatusUnauthorized)
		return
	}

	redirectURI := buildRedirectURI(context)

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func (a *routes) ProcessAuthorization(w http.ResponseWriter, r *http.Request) {
}

func parse(qs url.Values) authorization.AuthorizationRequest {
	return authorization.AuthorizationRequest{
		ClientID:    qs.Get("client_id"),
		GrantType:   qs.Get("grant_type"),
		RedirectURI: qs.Get("redirect_uri"),
		Scope:       strings.Split(qs.Get("scope"), " "),
		State:       qs.Get("state"),
	}
}

func buildRedirectURI(ctx authorization.AuthozirationContext) string {
	qs := url.Values{}
	qs.Add("client_id", ctx.ClientID)
	qs.Add("requested_scopes", strings.Join(ctx.RequestedScopes, " "))
	qs.Add("context", ctx.SignedAuthorizationRequest)

	return ctx.AuthorizationURL + "?" + qs.Encode()
}
