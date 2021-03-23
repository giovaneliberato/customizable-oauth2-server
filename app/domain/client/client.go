package client

type Client struct {
	ID                  string
	Secret              string
	AllowedRedirectUrls []string
	AllowedGrantTypes   []string
	AllowedScopes       []string
}

type Service interface {
	GetByID(ID string) Client
}

type service struct {
}

func NewService() Service {
	return &service{}
}

// Only for now
func (s *service) GetByID(ID string) Client {
	return Client{
		ID:                  "test-id",
		AllowedRedirectUrls: []string{"https://test.client/oauth2-callback"},
		AllowedGrantTypes:   []string{"authorization_code"},
		AllowedScopes:       []string{"profile", "contacts", "messages"},
	}

}
