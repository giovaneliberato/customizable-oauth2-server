package authorization

import (
	"oauth2-server/domain"
	"oauth2-server/domain/client"
	"oauth2-server/domain/context"
	"oauth2-server/domain/token"

	"github.com/spf13/viper"
)

type Service interface {
	Authorize(Authorization) (AuthorizationContext, *domain.OAuthError)
	ApproveAuthorization(AuthorizationApproval) (AuthorizationReponse, *domain.OAuthError)
	ExchangeAuthorizationCode(AuthorizationCodeExchange) (AuthorizationReponse, *domain.OAuthError)
}

type service struct {
	clientService    client.Service
	contextSigner    context.Signer
	tokenService     token.Service
	authorizationURL string
}

func NewService(clientService client.Service, signer context.Signer, tokenService token.Service) Service {
	return &service{
		clientService:    clientService,
		tokenService:     tokenService,
		contextSigner:    signer,
		authorizationURL: viper.GetString("authorization.consent-url"),
	}
}

func (s *service) Authorize(auth Authorization) (AuthorizationContext, *domain.OAuthError) {
	client := s.clientService.GetByID(auth.ClientID)

	err := Validate(client, auth)
	if err != nil {
		return AuthozirationContext{}, err
	}

	ctx := AuthorizationContext{
		AuthorizationURL:           s.authorizationURL,
		ClientID:                   client.ID,
		ClientName:                 client.Name,
		RequestedScopes:            auth.Scope,
		SignedAuthorizationContext: s.buildAuthorizationContext(auth),
	}

	return ctx, nil
}

func (s *service) ApproveAuthorization(approval AuthorizationApproval) (AuthorizationReponse, *domain.OAuthError) {
	context, err := s.contextSigner.VerifyAndDecode(approval.SignedAuthorizationRequest)

	if err != nil {
		return AuthorizationReponse{}, domain.InvalidApproveAuthorizationError
	}

	if !approval.ApprovedByUser {
		resp := AuthorizationReponse{
			RedirectURI: context.RedirectURI,
			State:       context.State,
		}

		return resp, domain.AccessDeniedError
	}

	signedAuthorizationCode := s.buildAuthorizationCodeContext(context, approval)

	response := AuthorizationReponse{
		SignedAuthorizationCode: signedAuthorizationCode,
		State:                   context.State,
		ResponseType:            context.ResponseType,
		RedirectURI:             context.RedirectURI,
	}

	if In("token", context.ResponseType) {
		response.AccessToken, err = s.tokenService.ExchangeWithoutValidation(signedAuthorizationCode)
	}

	if !In("code", context.ResponseType) {
		response.SignedAuthorizationCode = ""
	}

	return response, nil
}

func (s *service) ExchangeAuthorizationCode(r AuthorizationCodeExchange) (AuthorizationReponse, *domain.OAuthError) {
	return AuthorizationReponse{}, nil
}

func (s *service) buildAuthorizationContext(auth Authorization) string {
	context := context.Context{
		ClientID:     auth.ClientID,
		State:        auth.State,
		Scope:        auth.Scope,
		ResponseType: auth.ResponseType,
		RedirectURI:  auth.RedirectURI,
	}

	signedContext, _ := s.contextSigner.SignAndEncode(context)
	return signedContext
}

func (s *service) buildAuthorizationCodeContext(ctx context.Context, approval AuthorizationApproval) string {
	context := context.Context{
		ClientID:          ctx.ClientID,
		Scope:             ctx.Scope,
		RedirectURI:       ctx.RedirectURI,
		ResponseType:      ctx.ResponseType,
		AuthorizationCode: approval.AuthorizationCode,
	}

	signedContext, _ := s.contextSigner.SignAndEncode(context)
	return signedContext
}
