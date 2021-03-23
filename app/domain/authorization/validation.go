package authorization

import "goauth-extension/app/domain/client"

type ValidationError struct {
	Err              string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	Abort            bool   `json:"-"`
}

func (v *ValidationError) Empty() bool {
	return v.Err == ""
}

func (v *ValidationError) HasErrors() bool {
	return !v.Empty()
}

func (v *ValidationError) Error() string {
	return v.ErrorDescription
}

func Validate(client client.Client, data AuthorizationRequest) *ValidationError {
	if client.ID == "" || client.ID != data.ClientID {
		return &ValidationError{"invalid_request", "Invalid client details", true}
	}

	if notIn(data.RedirectURI, client.AllowedRedirectUrls) {
		return &ValidationError{"invalid_request", "Invalid client details", true}
	}

	if notIn(data.GrantType, client.AllowedGrantTypes) {
		return &ValidationError{"unsupported_response_type", "Unsupported grant type", false}
	}

	if oneItemNotIn(data.Scope, client.AllowedScopes) {
		return &ValidationError{"invalid_scope", "Requested scopes are not valid", false}
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
