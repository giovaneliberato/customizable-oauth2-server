package routes

import (
	"goauth-extension/app/domain/authorization"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi"
)

// AuthorizationRoutes returns a chi.Router with all authorization routes mapped
func AuthorizationRoutes() chi.Router {
	router := chi.NewRouter()

	router.Get("/oauth2/authorize", authorize)

	return router
}

func authorize(w http.ResponseWriter, r *http.Request) {
	authRequest := parse(r.URL.Query())

	authorization.Do(authRequest)

	http.Redirect(w, r, "/oauth2/consent", http.StatusFound)
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
