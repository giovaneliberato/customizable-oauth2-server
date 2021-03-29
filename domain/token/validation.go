package token

import (
	"bytes"
	"oauth2-server/domain"
	"oauth2-server/domain/client"
	"oauth2-server/domain/context"
)

func ValidateContext(req AuthorizationCodeRequest, ctx context.Context) *domain.OAuthError {
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
