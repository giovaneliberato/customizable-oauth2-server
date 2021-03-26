package token

import (
	"bytes"
	"goauth-extension/app/domain"
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/client"
)

func ValidateContext(req AuthorizationCodeRequest, ctx authorization.Context) *domain.OAuthError {
	if req.ClientID != ctx.ClientID {
		return domain.InvalidClientError
	}

	return nil
}

func ValidateClient(req AuthorizationCodeRequest, c client.Client) *domain.OAuthError {
	if c.ID == "" || c.ID != req.ClientID {
		return domain.InvalidClientError
	}

	if bytes.Compare([]byte(c.HashedSecret), client.HashSecret(req.ClientSecret)) != 0 {
		return domain.InvalidClientError
	}
	return nil
}
