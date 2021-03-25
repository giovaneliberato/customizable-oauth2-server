package routes

import (
	"encoding/json"
	"goauth-extension/app/domain"
	"goauth-extension/app/domain/authorization"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi"
	"github.com/golobby/container/v2"
)

func AuthorizationRouter(r *chi.Mux) {

	var route AuthorizationRoutes
	container.Make(&route)

	r.Get("/oauth2/authorize", route.Authorize)
	r.Post("/oauth2/approve-authorization", route.ProcessAuthorization)
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
	authRequest := parse(r.URL.Query())

	context, err := a.service.Authorize(authRequest)

	if err != nil {
		proccessError(w, r, authRequest.RedirectURI, authRequest.State, err)
		return
	}

	redirectURI := buildApprovalRedirectURI(context)

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func (a *authorizationRoutes) ProcessAuthorization(w http.ResponseWriter, r *http.Request) {
	approvalRequest := parseForm(r)
	resp, err := a.service.ApproveAuthorization(approvalRequest)

	if err != nil {
		proccessError(w, r, resp.RedirectURI, resp.State, err)
		return
	}

	redirectURI := buildClientCallbackRedirectURI(resp)

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func proccessError(w http.ResponseWriter, r *http.Request, errorRedirectURL, state string, err *domain.OAuthError) {
	if err.Abort {
		// This avoid open redirect attacks
		jsonBody, _ := json.Marshal(err)
		http.Error(w, string(jsonBody), http.StatusUnauthorized)
	} else {
		qs := url.Values{}
		qs.Add("error", err.Err)
		qs.Add("error_description", err.ErrorDescription)
		qs.Add("state", state)
		errorRedirectURL += "?" + qs.Encode()
		http.Redirect(w, r, errorRedirectURL, http.StatusFound)
	}
}

func parse(qs url.Values) authorization.AuthorizationRequest {
	return authorization.AuthorizationRequest{
		ClientID:    qs.Get("client_id"),
		GrantType:   qs.Get("response_type"),
		RedirectURI: qs.Get("redirect_uri"),
		Scope:       strings.Split(qs.Get("scope"), " "),
		State:       qs.Get("state"),
	}
}

func parseForm(r *http.Request) authorization.ApproveAuthorizationRequest {
	approved, _ := strconv.ParseBool(r.FormValue("approved"))
	return authorization.ApproveAuthorizationRequest{
		ApprovedByUser:             approved,
		AuthorizationCode:          r.FormValue("authorization_code"),
		SignedAuthorizationRequest: r.FormValue("signed_context"),
	}
}

func buildApprovalRedirectURI(ctx authorization.AuthozirationContext) string {
	qs := url.Values{}
	qs.Add("client_id", ctx.ClientID)
	qs.Add("requested_scopes", strings.Join(ctx.RequestedScopes, " "))
	qs.Add("signed_context", ctx.SignedAuthorizationContext)

	return ctx.AuthorizationURL + "?" + qs.Encode()
}

func buildClientCallbackRedirectURI(resp authorization.AuthorizationReponse) string {
	qs := url.Values{}
	qs.Add("state", resp.State)
	qs.Add("code", resp.SignedAuthorizationCode)

	return resp.RedirectURI + "?" + qs.Encode()
}
