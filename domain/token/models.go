package token

type AuthorizationCodeRequest struct {
	ClientID                string
	ClientSecret            string
	GrantType               string
	SignedAuthorizationCode string
}

type RefreshTokenRequest struct {
	ClientID     string
	ClientSecret string
	GrantType    string
	RefreshToken string
}

type AccessTokenResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
	Scope        []string `json:"scope,omitempty"`
}
