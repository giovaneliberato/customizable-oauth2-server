package domain

import "net/url"

type Client struct {
	ID                  string
	Secret              string
	AllowedRedirectUrls []url.URL
	AllowedGrantTypes   []string
	AllowedScopes       []string
}
