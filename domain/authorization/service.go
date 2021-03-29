package authorization

import (
	"oauth2-server/domain"
	"oauth2-server/domain/client"
	"oauth2-server/domain/context"

	"github.com/spf13/viper"
)

type Service interface {
	Authorize(Authorization) (AuthozirationContext, *domain.OAuthError)
	ApproveAuthorization(AuthorizationApproval) (AuthorizationReponse, *domain.OAuthError)
	ExchangeAuthorizationCode(AuthorizationCodeExchange) (AuthorizationReponse, *domain.OAuthError)
}

type service struct {
	client           client.Service
	contextSigner    context.Signer
	authorizationURL string
}

func NewService(client client.Service, signer context.Signer) Service {
	return &service{
		client:           client,
		contextSigner:    signer,
		authorizationURL: viper.GetString("authorization.consent-url"),
	}
}

func (s *service) Authorize(auth Authorization) (AuthozirationContext, *domain.OAuthError) {
	client := s.client.GetByID(auth.ClientID)

	err := Validate(client, auth)
	if err != nil {
		return AuthozirationContext{}, err
	}

	ctx := AuthozirationContext{
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

	return AuthorizationReponse{
		SignedAuthorizationCode: signedAuthorizationCode,
		State:                   context.State,
		RedirectURI:             context.RedirectURI,
	}, nil
}

func (s *service) ExchangeAuthorizationCode(r AuthorizationCodeExchange) (AuthorizationReponse, *domain.OAuthError) {
	return AuthorizationReponse{}, nil
}

func (s *service) buildAuthorizationContext(auth Authorization) string {
	context := context.Context{
		ClientID:    auth.ClientID,
		State:       auth.State,
		Scope:       auth.Scope,
		RedirectURI: auth.RedirectURI,
	}

	signedContext, _ := s.contextSigner.SignAndEncode(context)
	return signedContext
}

func (s *service) buildAuthorizationCodeContext(ctx context.Context, approval AuthorizationApproval) string {
	context := context.Context{
		ClientID:          ctx.ClientID,
		Scope:             ctx.Scope,
		RedirectURI:       ctx.RedirectURI,
		AuthorizationCode: approval.AuthorizationCode,
	}

	signedContext, _ := s.contextSigner.SignAndEncode(context)
	return signedContext
}
