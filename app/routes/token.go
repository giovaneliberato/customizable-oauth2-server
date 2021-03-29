package routes

import (
	"encoding/json"
	"net/http"
	"oauth2-server/domain"
	"oauth2-server/domain/token"

	"github.com/go-chi/chi"
	"github.com/golobby/container/v2"
)

func TokenRouter(r *chi.Mux) {
	var route TokenRoutes
	container.Make(&route)

	r.Post("/oauth2/token", route.ExchangeOrRefresh)
}

type TokenRoutes interface {
	ExchangeOrRefresh(http.ResponseWriter, *http.Request)
}

type tokenRoutes struct {
	service token.Service
}

func NewTokenRoutes(service token.Service) TokenRoutes {
	return &tokenRoutes{
		service: service,
	}
}

func (t *tokenRoutes) ExchangeOrRefresh(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("grant_type") == "authorization_code" {
		t.exchange(w, r)
		return
	}

	if r.FormValue("grant_type") == "refresh_token" {
		t.refresh(w, r)
		return
	}

	renderErrorWithStatus(w, r, domain.InvalidGrantTypeError, http.StatusBadRequest)
}

func (t *tokenRoutes) exchange(w http.ResponseWriter, r *http.Request) {
	authCodeRequest, err := parseAuthorizationCodeRequest(r)
	if err != nil {
		renderErrorWithStatus(w, r, err, http.StatusBadRequest)
		return
	}

	accessToken, err := t.service.Exchange(authCodeRequest)
	if err != nil {
		renderErrorWithStatus(w, r, err, http.StatusBadRequest)
		return
	}

	jsonBody, _ := json.Marshal(accessToken)
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBody)
}

func (t *tokenRoutes) refresh(w http.ResponseWriter, r *http.Request) {
	refreshTokenRequest, err := parseRefreshTokenRequest(r)
	if err != nil {
		renderErrorWithStatus(w, r, err, http.StatusBadRequest)
		return
	}

	accessToken, err := t.service.Refresh(refreshTokenRequest)
	if err != nil {
		renderErrorWithStatus(w, r, err, http.StatusBadRequest)
		return
	}

	jsonBody, _ := json.Marshal(accessToken)
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBody)
}
