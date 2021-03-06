package routes

import (
	"fmt"
	"net/http"
	"net/url"
	"oauth2-server/domain/authorization"
	"strings"

	"github.com/go-chi/chi"
	"github.com/golobby/container/v2"
)

func AuthorizationRouter(r *chi.Mux) {

	var route AuthorizationRoutes
	container.Make(&route)

	r.Get("/oauth2/authorize", route.Authorize)
	r.Get("/oauth2/approve-authorization", route.ProcessAuthorization)
}

type AuthorizationRoutes interface {
	Authorize(http.ResponseWriter, *http.Request)
	ProcessAuthorization(http.ResponseWriter, *http.Request)
}

type authorizationRoutes struct {
	service authorization.Service
}

func NewAuthorizationRoutes(service authorization.Service) AuthorizationRoutes {
	return &authorizationRoutes{
		service: service,
	}
}

func (a *authorizationRoutes) Authorize(w http.ResponseWriter, r *http.Request) {
	authRequest, err := parseAuthorizationRequest(r.URL.Query())
	if err != nil {
		renderErrorWithStatus(w, r, err, http.StatusBadRequest)
		return
	}

	context, err := a.service.Authorize(authRequest)
	if err != nil {
		proccessError(w, r, authRequest.RedirectURI, authRequest.State, err)
		return
	}

	redirectURI := buildApprovalRedirectURI(context)
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func (a *authorizationRoutes) ProcessAuthorization(w http.ResponseWriter, r *http.Request) {
	approvalRequest, err := parseAuthorizationApproval(r.URL.Query())
	if err != nil {
		renderErrorWithStatus(w, r, err, http.StatusBadRequest)
		return
	}
	resp, err := a.service.ApproveAuthorization(approvalRequest)

	if err != nil {
		proccessError(w, r, resp.RedirectURI, resp.State, err)
		return
	}

	redirectURI := buildClientCallbackRedirectURI(resp)

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func buildApprovalRedirectURI(ctx authorization.AuthorizationContext) string {
	qs := url.Values{}
	qs.Add("client_id", ctx.ClientID)
	qs.Add("client_name", ctx.ClientName)
	qs.Add("requested_scopes", strings.Join(ctx.RequestedScopes, " "))
	qs.Add("signed_context", ctx.SignedAuthorizationContext)

	return ctx.AuthorizationURL + "?" + qs.Encode()
}

func buildClientCallbackRedirectURI(resp authorization.AuthorizationReponse) string {
	qs := url.Values{}
	qs.Add("state", resp.State)

	if authorization.In("code", resp.ResponseType) {
		qs.Add("code", resp.SignedAuthorizationCode)
	}

	if authorization.In("token", resp.ResponseType) {
		qs.Add("access_token", resp.AccessToken.AccessToken)
		qs.Add("refresh_token", resp.AccessToken.RefreshToken)
		qs.Add("token_type", resp.AccessToken.TokenType)
		qs.Add("expires_in", fmt.Sprint(resp.AccessToken.ExpiresIn))
	}

	return resp.RedirectURI + "?" + qs.Encode()
}
