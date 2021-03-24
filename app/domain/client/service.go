package client

import (
	"crypto/sha512"
	"errors"
	"net/url"

	"github.com/spf13/viper"
)

type Service interface {
	GetByID(string) Client
	Save(Client) error
	ValidateSecret(Client, string) error
}

type service struct {
	repository Repository
}

func NewService(r Repository) Service {
	return &service{
		repository: r,
	}
}

func (s *service) GetByID(ID string) Client {
	return s.repository.GetByID(ID)
}

func (s *service) Save(c Client) error {
	err := validate(c)
	if err != nil {
		return err
	}

	c.HashedSecret = hashSecret(c.RawSecret)
	c.RawSecret = ""
	s.repository.Save(c)

	return nil
}

func (s *service) ValidateSecret(c Client, secret string) error {
	return nil
}

func hashSecret(rawSecret string) []byte {
	hash := sha512.New()
	hash.Write([]byte(rawSecret))
	return hash.Sum(nil)
}

func validate(c Client) error {
	if !supportedGrantType(c.AllowedGrantTypes) {
		return errors.New("Grant type not supported")
	}

	if len(c.AllowedRedirectUrls) == 0 {
		return errors.New("No Redirect URLs provided")
	}

	if anyMalformedURL(c.AllowedRedirectUrls) {
		return errors.New("The request contains malformed redirect urls")
	}

	if len(c.AllowedScopes) == 0 {
		return errors.New("No allowed scopes provided")
	}
	return nil
}

func supportedGrantType(grants []string) bool {
	for _, supportedGrant := range viper.GetStringSlice("oauth2-server.supported-grant-types") {
		for _, grant := range grants {
			if supportedGrant == grant {
				return true
			}
		}
	}
	return false
}

func anyMalformedURL(urls []string) bool {
	for _, u := range urls {
		_, err := url.Parse(u)
		if u == "" || err != nil {
			return true
		}
	}
	return false
}
