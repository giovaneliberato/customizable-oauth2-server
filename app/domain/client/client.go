package client

type Client struct {
	ID                  string
	Secret              string
	AllowedRedirectUrls []string
	AllowedGrantTypes   []string
	AllowedScopes       []string
}

func GetClientByID(ID string) Client {
	return Client{}
}
