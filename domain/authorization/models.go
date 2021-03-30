package authorization

import "oauth2-server/domain/token"

type Authorization struct {
	ClientID     string
	ResponseType []string
	RedirectURI  string
	Scope        []string
	State        string
}

type AuthorizationApproval struct {
	ApprovedByUser             bool
	AuthorizationCode          string
	SignedAuthorizationRequest string
}

type AuthozirationContext struct {
	AuthorizationURL           string
	ClientID                   string
	ClientName                 string
	RequestedScopes            []string
	SignedAuthorizationContext string
}

type AuthorizationReponse struct {
	RedirectURI             string
	State                   string
	ResponseType            []string
	AccessToken             token.AccessTokenResponse
	SignedAuthorizationCode string
}

type AuthorizationCodeExchange struct {
	ClientID                string
	ClientSecret            string
	ResponseType            string
	SignedAuthorizationCode string
}
