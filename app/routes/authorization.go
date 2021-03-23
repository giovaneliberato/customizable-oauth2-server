package routes

import (
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

	return router
}

type AuthorizationRoutes interface {
	Authorize(http.ResponseWriter, *http.Request)
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
		if err.Abort {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
	}

	redirectURI := buildRedirectURI(context)

	http.Redirect(w, r, redirectURI, http.StatusFound)
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
