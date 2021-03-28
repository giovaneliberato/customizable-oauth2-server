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
