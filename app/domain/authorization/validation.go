package authorization

import "goauth-extension/app/domain/client"

func Validate(client client.Client, data AuthorizationRequest) *AuthorizationError {
	if client.ID == "" || client.ID != data.ClientID {
		return InvalidClientError
	}

	if notIn(data.RedirectURI, client.AllowedRedirectUrls) {
		return InvalidClientError
	}

	if notIn(data.GrantType, client.AllowedGrantTypes) {
		return UnsupportedResponseTypeError
	}

	if oneItemNotIn(data.Scope, client.AllowedScopes) {
		return InvalidScopeError
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
