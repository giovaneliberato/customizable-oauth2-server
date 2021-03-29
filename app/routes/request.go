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

func parseAuthorizationRequest(qs url.Values) (authorization.AuthorizationRequest, *domain.OAuthError) {
	required := []string{
		qs.Get("client_id"),
		qs.Get("response_type"),
		qs.Get("redirect_uri"),
		qs.Get("scope"),
		qs.Get("state"),
	}

	if anyValueMissing(required) {
		return authorization.AuthorizationRequest{}, domain.InvalidAuthorizationCodeRequestError
	}

	return authorization.AuthorizationRequest{
		ClientID:     qs.Get("client_id"),
		ResponseType: qs.Get("response_type"),
		RedirectURI:  qs.Get("redirect_uri"),
		Scope:        strings.Split(qs.Get("scope"), " "),
		State:        qs.Get("state"),
	}, nil
}

func parseAuthorizationApproval(r *http.Request) (authorization.ApproveAuthorizationRequest, *domain.OAuthError) {
	required := []string{
		r.FormValue("approved"),
		r.FormValue("authorization_code"),
		r.FormValue("signed_context"),
	}

	approved, err := strconv.ParseBool(r.FormValue("approved"))
	if anyValueMissing(required) || err != nil {
		return authorization.ApproveAuthorizationRequest{}, domain.InvalidAuthorizationCodeRequestError
	}

	return authorization.ApproveAuthorizationRequest{
		ApprovedByUser:             approved,
		AuthorizationCode:          r.FormValue("authorization_code"),
		SignedAuthorizationRequest: r.FormValue("signed_context"),
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