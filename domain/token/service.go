package token

import (
	"oauth2-server/domain"
	"oauth2-server/domain/client"
	"oauth2-server/domain/context"
)

type Service interface {
	Exchange(AuthorizationCodeRequest) (AccessTokenResponse, *domain.OAuthError)
	Refresh(RefreshTokenRequest) (AccessTokenResponse, *domain.OAuthError)
}

type service struct {
	clientService         client.Service
	externalServiceClient ExternalServiceClient
	contextSigner         context.Signer
}

func NewService(clientService client.Service, contextSigner context.Signer, externalServiceClient ExternalServiceClient) Service {
	return &service{
		clientService:         clientService,
		contextSigner:         contextSigner,
		externalServiceClient: externalServiceClient,
	}
}

func (s *service) Exchange(req AuthorizationCodeRequest) (AccessTokenResponse, *domain.OAuthError) {
	ctx, err := s.contextSigner.VerifyAndDecode(req.SignedAuthorizationCode)

	if err != nil {
		return AccessTokenResponse{}, domain.InvalidAuthorizationCodeRequestError
	}

	if err := ValidateContext(req, ctx); err != nil {
		return AccessTokenResponse{}, err
	}

	client := s.clientService.GetByID(req.ClientID)

	if err := ValidateClient(req.ClientID, req.ClientSecret, client); err != nil {
		return AccessTokenResponse{}, err
	}

	accessToken, externalErr := s.externalServiceClient.GetAccessToken(ctx)
	if externalErr != nil {
		return AccessTokenResponse{}, externalErr
	}

	return accessToken, nil
}

func (s *service) Refresh(req RefreshTokenRequest) (AccessTokenResponse, *domain.OAuthError) {
	if req.GrantType != "refresh_token" {
		return AccessTokenResponse{}, domain.InvalidGrantTypeError
	}

	client := s.clientService.GetByID(req.ClientID)
	if err := ValidateClient(req.ClientID, req.ClientSecret, client); err != nil {
		return AccessTokenResponse{}, err
	}

	accessToken, externalErr := s.externalServiceClient.RefreshAccessToken(req.RefreshToken)
	if externalErr != nil {
		return AccessTokenResponse{}, externalErr
	}

	return accessToken, nil
}
