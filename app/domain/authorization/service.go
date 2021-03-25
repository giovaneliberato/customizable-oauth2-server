package authorization

import (
	"goauth-extension/app/domain"
	"goauth-extension/app/domain/client"

	"github.com/spf13/viper"
)

type Service interface {
	Authorize(AuthorizationRequest) (AuthozirationContext, *domain.OAuthError)
	ApproveAuthorization(ApproveAuthorizationRequest) (AuthorizationReponse, *domain.OAuthError)
	ExchangeAuthorizationCode(ExchangeAuthorizationCodeRequest) (AuthorizationReponse, *domain.OAuthError)
}

type service struct {
	client           client.Service
	tokenSigner      TokenSigner
	authorizationURL string
}

func NewService(client client.Service, signer TokenSigner) Service {
	return &service{
		client:           client,
		tokenSigner:      signer,
		authorizationURL: viper.GetString("authorization.consent-url"),
	}
}

func (s *service) Authorize(request AuthorizationRequest) (AuthozirationContext, *domain.OAuthError) {
	client := s.client.GetByID(request.ClientID)

	err := Validate(client, request)
	if err != nil {
		return AuthozirationContext{}, err
	}

	ctx := AuthozirationContext{
		AuthorizationURL:           s.authorizationURL,
		ClientID:                   client.ID,
		RequestedScopes:            request.Scope,
		SignedAuthorizationContext: s.buildAuthorizationContext(request),
	}

	return ctx, nil
}

func (s *service) ApproveAuthorization(approveAuthorization ApproveAuthorizationRequest) (AuthorizationReponse, *domain.OAuthError) {
	claims, err := s.tokenSigner.VerifyAndDecode(approveAuthorization.SignedAuthorizationRequest)

	if err != nil {
		return AuthorizationReponse{}, domain.InvalidApproveAuthorizationError
	}

	if !approveAuthorization.ApprovedByUser {
		resp := AuthorizationReponse{
			RedirectURI: claims.RedirectURI,
			State:       claims.State,
		}

		return resp, domain.AccessDeniedError
	}

	signedAuthorizationCode := s.buildAuthorizationCodeToken(claims, approveAuthorization)

	return AuthorizationReponse{
		SignedAuthorizationCode: signedAuthorizationCode,
		State:                   claims.State,
		RedirectURI:             claims.RedirectURI,
	}, nil
}

func (s *service) ExchangeAuthorizationCode(r ExchangeAuthorizationCodeRequest) (AuthorizationReponse, *domain.OAuthError) {
	return AuthorizationReponse{}, nil
}

func (s *service) buildAuthorizationContext(req AuthorizationRequest) string {
	claims := ContextClaims{
		ClientID:    req.ClientID,
		State:       req.State,
		Scope:       req.Scope,
		RedirectURI: req.RedirectURI,
	}

	tokenString, _ := s.tokenSigner.SignAndEncode(claims)
	return tokenString
}

func (s *service) buildAuthorizationCodeToken(ctx ContextClaims, approveAuthorization ApproveAuthorizationRequest) string {
	claims := ContextClaims{
		ClientID:          ctx.ClientID,
		Scope:             ctx.Scope,
		RedirectURI:       ctx.RedirectURI,
		AuthorizationCode: approveAuthorization.AuthorizationCode,
	}

	tokenString, _ := s.tokenSigner.SignAndEncode(claims)
	return tokenString
}
