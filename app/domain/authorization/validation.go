package authorization

import (
	"goauth-extension/app/domain"
	"goauth-extension/app/domain/client"
)

func Validate(client client.Client, data AuthorizationRequest) *domain.OAuthError {
	if client.ID == "" || client.ID != data.ClientID {
		return domain.InvalidClientError
	}

	if notIn(data.RedirectURI, client.AllowedRedirectUrls) {
		return domain.InvalidClientError
	}

	if notIn(data.ResponseType, client.AllowedResponseTypes) {
		return domain.UnsupportedResponseTypeError
	}

	if oneItemNotIn(data.Scope, client.AllowedScopes) {
		return domain.InvalidScopeError
	}

	return nil
}

func oneItemNotIn(query []string, set []string) bool {
	for _, q := range query {
		if notIn(q, set) {
			return true
		}
	}
	return false
}

func notIn(query string, set []string) bool {
	for _, item := range set {
		if item == query {
			return false
		}
	}
	return true
}
