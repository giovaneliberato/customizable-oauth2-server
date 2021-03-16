package routes

import (
	"goauth-extension/app/domain"
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
	//authReq := parse(r.URL.Query())

	http.Redirect(w, r, "/oauth2/consent", http.StatusFound)
}

func parse(qs url.Values) domain.AuthorizationRequest {
	return domain.AuthorizationRequest{
		ClientID:    qs.Get("client_id"),
		GrantType:   qs.Get("grant_type"),
		RedirectURI: qs.Get("redirect_uri"),
		Scope:       strings.Split(qs.Get("scope"), " "),
		State:       qs.Get("state"),
	}
}
