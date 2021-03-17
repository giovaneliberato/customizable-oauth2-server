package authorization

import (
	"goauth-extension/app/domain"
)

type ValidationError struct {
	Error            string
	ErrorDescription string
}

func (v *ValidationError) Empty() bool {
	return v.Error == ""
}

func Validate(client domain.Client, data AuthorizationRequest) ValidationError {
	if client.ID != data.ClientID {
		return ValidationError{"invalid_request", "Invalid client"}
	}

	if notIn(data.RedirectURI, client.AllowedRedirectUrls) {
		return ValidationError{"invalid_request", "Invalid client details"}
	}

	if notIn(data.GrantType, client.AllowedGrantTypes) {
		return ValidationError{"unauthorized_client", "Unsupported grant type"}
	}

	if oneItemNotIn(data.Scope, client.AllowedScopes) {
		return ValidationError{"invalid_scope", "Requested scopes are not valid"}
	}

	return ValidationError{}
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
