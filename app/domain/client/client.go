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

func (s *service) GetByID(ID string) Client {
	return Client{}
}
