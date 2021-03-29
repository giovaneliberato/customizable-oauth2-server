package token

import (
	"oauth2-server/domain"
	"oauth2-server/domain/authorization"
	"oauth2-server/domain/client"
	"oauth2-server/domain/context"
	"oauth2-server/infra"
)

type Service interface {
	Exchange(AuthorizationCodeRequest) (authorization.AccessTokenResponse, *domain.OAuthError)
	Refresh(RefreshTokenRequest) (authorization.AccessTokenResponse, *domain.OAuthError)
}

type service struct {
	clientService         client.Service
	externalServiceClient infra.ExternalServiceClient
	contextSigner         context.Signer
}

func NewService(clientService client.Service, contextSigner context.Signer, externalServiceClient infra.ExternalServiceClient) Service {
	return &service{
		clientService:         clientService,
		contextSigner:         contextSigner,
		externalServiceClient: externalServiceClient,
	}
}

func (s *service) Exchange(req AuthorizationCodeRequest) (authorization.AccessTokenResponse, *domain.OAuthError) {
	ctx, err := s.contextSigner.VerifyAndDecode(req.SignedAuthorizationCode)

	if err != nil {
		return authorization.AccessTokenResponse{}, domain.InvalidAuthorizationCodeRequestError
	}

	if err := ValidateContext(req, ctx); err != nil {
		return authorization.AccessTokenResponse{}, err
	}

	client := s.clientService.GetByID(req.ClientID)

	if err := ValidateClient(req.ClientID, req.ClientSecret, client); err != nil {
		return authorization.AccessTokenResponse{}, err
	}

	accessToken, externalErr := s.externalServiceClient.GetAccessToken(ctx)
	if externalErr != nil {
		return authorization.AccessTokenResponse{}, externalErr
	}

	return accessToken, nil
}

func (s *service) Refresh(req RefreshTokenRequest) (authorization.AccessTokenResponse, *domain.OAuthError) {
	if req.GrantType != "refresh_token" {
		return authorization.AccessTokenResponse{}, domain.InvalidGrantTypeError
	}

	client := s.clientService.GetByID(req.ClientID)
	if err := ValidateClient(req.ClientID, req.ClientSecret, client); err != nil {
		return authorization.AccessTokenResponse{}, err
	}

	accessToken, externalErr := s.externalServiceClient.RefreshAccessToken(req.RefreshToken)
	if externalErr != nil {
		return authorization.AccessTokenResponse{}, externalErr
	}

	return accessToken, nil
}
