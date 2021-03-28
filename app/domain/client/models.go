package client

type Client struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	RawSecret            string   `json:"secret"`
	HashedSecret         []byte   `json:"-"`
	AllowedRedirectUrls  []string `json:"allowed_redirect_urls"`
	AllowedResponseTypes []string `json:"allowed_response_types"`
	AllowedScopes        []string `json:"allowed_scopes"`
}
