package authorization

import (
	"oauth2-server/domain"
	"oauth2-server/domain/client"
)

func Validate(client client.Client, auth Authorization) *domain.OAuthError {
	if client.ID == "" || client.ID != auth.ClientID {
		return domain.InvalidClientError
	}

	if notIn(auth.RedirectURI, client.AllowedRedirectUrls) {
		return domain.InvalidClientError
	}

	if oneItemNotIn(auth.ResponseType, client.AllowedResponseTypes) {
		return domain.UnsupportedResponseTypeError
	}

	if oneItemNotIn(auth.Scope, client.AllowedScopes) {
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
