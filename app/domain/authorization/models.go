package authorization

type AuthorizationRequest struct {
	ClientID    string
	GrantType   string
	RedirectURI string
	Scope       []string
	State       string
}

type ApproveAuthorizationRequest struct {
	ApprovedByUser             bool
	AuthorizationCode          string
	SignedAuthorizationRequest string
}

type AuthozirationContext struct {
	AuthorizationURL           string
	ClientID                   string
	RequestedScopes            []string
	SignedAuthorizationRequest string
}

type AuthorizationReponse struct {
	RedirectURI             string
	State                   string
	SignedAuthorizationCode string
}
