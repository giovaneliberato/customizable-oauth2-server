package token

import (
	"oauth2-server/app/domain"
	"oauth2-server/app/domain/authorization"
	"oauth2-server/app/domain/client"
)

type Service interface {
	Exchange(AuthorizationCodeRequest) (AccessTokenResponse, *domain.OAuthError)
	ExchangeWithoutValidation(string) (AccessTokenResponse, *domain.OAuthError)
	Refresh(RefreshTokenRequest) (AccessTokenResponse, *domain.OAuthError)
}

type service struct {
	clientService         client.Service
	externalServiceClient ExternalServiceClient
	contextSigner         authorization.ContextSigner
}

func NewService(clientService client.Service, contextSigner authorization.ContextSigner, externalServiceClient ExternalServiceClient) Service {
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

func (s *service) ExchangeWithoutValidation(signedAuthorizationCode string) (AccessTokenResponse, *domain.OAuthError) {
	ctx, err := s.contextSigner.VerifyAndDecode(signedAuthorizationCode)

	if err != nil {
		return AccessTokenResponse{}, domain.InvalidAuthorizationCodeRequestError
	}

	accessToken, externalErr := s.externalServiceClient.GetAccessToken(ctx)
	if externalErr != nil {
		return AccessTokenResponse{}, externalErr
	}

	return accessToken, nil
}

func (s *service) Refresh(req RefreshTokenRequest) (AccessTokenResponse, *domain.OAuthError) {
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
