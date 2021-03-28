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
	ClientName                 string
	RequestedScopes            []string
	SignedAuthorizationContext string
}

type AuthorizationReponse struct {
	RedirectURI             string
	State                   string
	AccessToken             AccessTokenResponse
	SignedAuthorizationCode string
}

type AccessTokenResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
	Scope        []string `json:"scope,omitempty"`
}

type ExchangeAuthorizationCodeRequest struct {
	ClientID                string
	ClientSecret            string
	ResponseType            string
	SignedAuthorizationCode string
}
