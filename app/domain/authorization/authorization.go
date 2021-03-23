package authorization

import (
	"goauth-extension/app/domain/client"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

// Authorization representing the data sent in the first request of the protocol
type AuthorizationRequest struct {
	ClientID    string
	GrantType   string
	RedirectURI string
	Scope       []string
	State       string
}

type AuthozirationContext struct {
	AuthorizationURL           string
	ClientID                   string
	RequestedScopes            []string
	SignedAuthorizationRequest string
}

type Service interface {
	Authorize(AuthorizationRequest) (AuthozirationContext, *ValidationError)
}

type service struct {
	client client.Service
}

func NewService(client client.Service) Service {
	return &service{
		client: client,
	}
}

func (s *service) Authorize(request AuthorizationRequest) (AuthozirationContext, *ValidationError) {
	client := s.client.GetByID(request.ClientID)

	err := Validate(client, request)
	if err != nil {
		return AuthozirationContext{}, err
	}

	ctx := AuthozirationContext{
		AuthorizationURL:           viper.GetString("authorization.login-url"),
		ClientID:                   client.ID,
		RequestedScopes:            request.Scope,
		SignedAuthorizationRequest: signAndEncode(request),
	}

	return ctx, nil
}

func signAndEncode(req AuthorizationRequest) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"client_id":    req.ClientID,
		"state":        req.State,
		"scopes":       req.Scope,
		"redirect_uri": req.RedirectURI,
		"nounce":       uuid.NewString(), // here to avoid replay attacks
	})

	key := viper.GetString("signing.key")
	tokenString, _ := token.SignedString([]byte(key))
	return tokenString
}
