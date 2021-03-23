package authorization

import (
	"goauth-extension/app/domain/client"
	"goauth-extension/app/infra/token"

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
	client      client.Service
	tokenSigner token.TokenSigner
}

func NewService(client client.Service, signer token.TokenSigner) Service {
	return &service{
		client:      client,
		tokenSigner: signer,
	}
}

func (s *service) Authorize(request AuthorizationRequest) (AuthozirationContext, *ValidationError) {
	client := s.client.GetByID(request.ClientID)

	err := Validate(client, request)
	if err != nil {
		return AuthozirationContext{}, err
	}

	ctx := AuthozirationContext{
		AuthorizationURL:           viper.GetString("authorization.consent-url"),
		ClientID:                   client.ID,
		RequestedScopes:            request.Scope,
		SignedAuthorizationRequest: s.buildToken(request),
	}

	return ctx, nil
}

func (s *service) buildToken(req AuthorizationRequest) string {
	claims := token.ContextClaims{
		ClientID:    req.ClientID,
		State:       req.State,
		Scope:       req.Scope,
		RedirectURI: req.RedirectURI,
	}

	tokenString, _ := s.tokenSigner.SignAndEncode(claims)
	return tokenString
}
