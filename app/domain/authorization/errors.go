package authorization

type AuthorizationError struct {
	Err              string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	Abort            bool   `json:"-"`
}

func (e *AuthorizationError) Empty() bool {
	return e.Err == ""
}

var InvalidApproveAuthorizationError = &AuthorizationError{
	Err:              "invalid_request",
	ErrorDescription: "Could not proccess approval request",
	Abort:            true,
}

var AccessDeniedError = &AuthorizationError{
	Err:              "access_denied",
	ErrorDescription: "The user or the authorization server denied the request",
	Abort:            false,
}

var InvalidClientError = &AuthorizationError{
	Err:              "invalid_request",
	ErrorDescription: "Invalid client details",
	Abort:            true,
}

var UnsupportedResponseTypeError = &AuthorizationError{
	Err:              "unsupported_response_type",
	ErrorDescription: "Unsupported response type",
	Abort:            false,
}

var InvalidScopeError = &AuthorizationError{
	Err:              "invalid_scope",
	ErrorDescription: "Requested scopes are not valid",
	Abort:            false,
}
