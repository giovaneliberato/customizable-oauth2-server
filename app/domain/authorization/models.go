package authorization

type AuthorizationRequest struct {
	ClientID     string
	ResponseType string
	RedirectURI  string
	Scope        []string
	State        string
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
	SignedAuthorizationContext string
}

type AuthorizationReponse struct {
	RedirectURI             string
	State                   string
	SignedAuthorizationCode string
}

type ExchangeAuthorizationCodeRequest struct {
	ClientID                string
	ClientSecret            string
	ResponseType            string
	SignedAuthorizationCode string
}
