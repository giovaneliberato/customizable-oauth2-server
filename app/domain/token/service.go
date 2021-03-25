package token

import (
	"goauth-extension/app/domain"
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/client"
)

type Service interface {
	Exchange(AuthorizationCodeRequest) (AccessTokenResponse, *domain.OAuthError)
}

type service struct {
	clientService         client.Service
	externalServiceClient ExternalServiceClient
	tokenSigner           authorization.TokenSigner
}

func NewService(clientService client.Service, tokenSigner authorization.TokenSigner, externalServiceClient ExternalServiceClient) Service {
	return &service{
		clientService:         clientService,
		tokenSigner:           tokenSigner,
		externalServiceClient: externalServiceClient,
	}
}

func (s *service) Exchange(req AuthorizationCodeRequest) (AccessTokenResponse, *domain.OAuthError) {
	ctx, err := s.tokenSigner.VerifyAndDecode(req.SignedAuthorizationCode)

	if err != nil {
		return AccessTokenResponse{}, domain.InvalidAuthorizationCodeRequestError
	}

	if err := ValidateContext(req, ctx); err != nil {
		return AccessTokenResponse{}, err
	}

	client := s.clientService.GetByID(req.ClientID)

	if err := ValidateClient(req, client); err != nil {
		return AccessTokenResponse{}, err
	}

	accessToken, externalErr := s.externalServiceClient.GetAccessToken(ctx)
	if err != nil {
		return AccessTokenResponse{}, externalErr
	}

	return accessToken, nil
}
