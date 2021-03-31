package routes

import (
	"net/http"
	"net/url"
	"oauth2-server/domain"
	"oauth2-server/domain/authorization"
	"oauth2-server/domain/token"
	"strconv"
	"strings"
)

func parseAuthorizationRequest(qs url.Values) (authorization.Authorization, *domain.OAuthError) {
	required := []string{
		qs.Get("client_id"),
		qs.Get("response_type"),
		qs.Get("redirect_uri"),
		qs.Get("scope"),
		qs.Get("state"),
	}

	if anyValueMissing(required) {
		return authorization.Authorization{}, domain.InvalidAuthorizationCodeRequestError
	}

	return authorization.Authorization{
		ClientID:     qs.Get("client_id"),
		ResponseType: strings.Split(qs.Get("response_type"), " "),
		RedirectURI:  qs.Get("redirect_uri"),
		Scope:        strings.Split(qs.Get("scope"), " "),
		State:        qs.Get("state"),
	}, nil
}

func parseAuthorizationApproval(qs url.Values) (authorization.AuthorizationApproval, *domain.OAuthError) {
	required := []string{
		qs.Get("approved"),
		qs.Get("authorization_code"),
		qs.Get("signed_context"),
	}

	approved, err := strconv.ParseBool(qs.Get("approved"))
	if anyValueMissing(required) || err != nil {
		return authorization.AuthorizationApproval{}, domain.InvalidAuthorizationCodeRequestError
	}

	return authorization.AuthorizationApproval{
		ApprovedByUser:             approved,
		AuthorizationCode:          qs.Get("authorization_code"),
		SignedAuthorizationRequest: qs.Get("signed_context"),
	}, nil
}

func parseRefreshTokenRequest(r *http.Request) (token.RefreshTokenRequest, *domain.OAuthError) {
	required := []string{
		r.FormValue("client_id"),
		r.FormValue("client_secret"),
		r.FormValue("grant_type"),
		r.FormValue("refresh_token"),
	}

	if anyValueMissing(required) {
		return token.RefreshTokenRequest{}, domain.InvalidRequestError
	}

	return token.RefreshTokenRequest{
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
		GrantType:    r.FormValue("grant_type"),
		RefreshToken: r.FormValue("refresh_token"),
	}, nil
}

func parseAuthorizationCodeRequest(r *http.Request) (token.AuthorizationCodeRequest, *domain.OAuthError) {
	required := []string{
		r.FormValue("client_id"),
		r.FormValue("client_secret"),
		r.FormValue("grant_type"),
		r.FormValue("code"),
	}

	if anyValueMissing(required) {
		return token.AuthorizationCodeRequest{}, domain.InvalidRequestError
	}

	return token.AuthorizationCodeRequest{
		ClientID:                r.FormValue("client_id"),
		ClientSecret:            r.FormValue("client_secret"),
		GrantType:               r.FormValue("grant_type"),
		SignedAuthorizationCode: r.FormValue("code"),
	}, nil
}

func anyValueMissing(values []string) bool {
	for _, v := range values {
		if v == "" {
			return true
		}
	}
	return false
}
