package client

type Client struct {
	ID                  string
	RawSecret           string
	HashedSecret        []byte
	AllowedRedirectUrls []string
	AllowedGrantTypes   []string
	AllowedScopes       []string
}
