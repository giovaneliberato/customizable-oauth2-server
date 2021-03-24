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

type ApproveAuthorizationRequest struct {
	ApprovedByUser             bool
	AuthorizationCode          string
	SignedAuthorizationRequest string
}

type AuthozirationContext struct {
	AuthorizationURL           string
	ClientID                   string
	RequestedScopes            []string
	SignedAuthorizationRequest string
}

type AuthorizationReponse struct {
	RedirectURI       string
	State             string
	AuthorizationCode string
}

type Service interface {
	Authorize(AuthorizationRequest) (AuthozirationContext, *ValidationError)
	ApproveAuthorization(ApproveAuthorizationRequest) (AuthorizationReponse, *ValidationError)
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

func (s *service) ApproveAuthorization(approveAuthorization ApproveAuthorizationRequest) (AuthorizationReponse, *ValidationError) {
	claims, err := s.tokenSigner.VerifyAndDecode(approveAuthorization.SignedAuthorizationRequest)

	if err != nil {
		return AuthorizationReponse{}, InvalidApproveAuthorizationError
	}

	if !approveAuthorization.ApprovedByUser {
		resp := AuthorizationReponse{
			RedirectURI: claims.RedirectURI,
			State:       claims.State,
		}

		return resp, AuthorizationDeniedError
	}

	return AuthorizationReponse{
		AuthorizationCode: approveAuthorization.AuthorizationCode,
		State:             claims.State,
		RedirectURI:       claims.RedirectURI,
	}, nil
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
