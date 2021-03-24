package client

type Client struct {
	ID                  string   `json:"client_id,required"`
	RawSecret           string   `json:"secret,required"`
	HashedSecret        []byte   `json:"-"`
	AllowedRedirectUrls []string `json:"allowed_redirect_urls,required"`
	AllowedGrantTypes   []string `json:"allowed_grant_types,required"`
	AllowedScopes       []string `json:"allowed_scopes,required"`
}
