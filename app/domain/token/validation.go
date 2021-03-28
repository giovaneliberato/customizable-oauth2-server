package token

import (
	"bytes"
	"oauth2-server/app/domain"
	"oauth2-server/app/domain/authorization"
	"oauth2-server/app/domain/client"
)

func ValidateContext(req AuthorizationCodeRequest, ctx authorization.Context) *domain.OAuthError {
	if req.ClientID != ctx.ClientID {
		return domain.InvalidClientError
	}

	return nil
}

func ValidateClient(reqClientID, recClientSecret string, c client.Client) *domain.OAuthError {
	if c.ID == "" || c.ID != reqClientID {
		return domain.InvalidClientError
	}

	if bytes.Compare([]byte(c.HashedSecret), client.HashSecret(recClientSecret)) != 0 {
		return domain.InvalidClientError
	}
	return nil
}
