package domain

type Client struct {
	ID                  string
	Secret              string
	AllowedRedirectUrls []string
	AllowedGrantTypes   []string
	AllowedScopes       []string
}
