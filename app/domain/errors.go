package domain

type OAuthError struct {
	Err              string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	Abort            bool   `json:"-"`
}

func (e *OAuthError) Empty() bool {
	return e.Err == ""
}

func (e *OAuthError) Error() string {
	return e.Err
}

var InvalidAuthorizationCodeRequestError = &OAuthError{
	Err:              "invalid_request",
	ErrorDescription: "Could not proccess authorization code request",
	Abort:            true,
}

var InvalidApproveAuthorizationError = &OAuthError{
	Err:              "invalid_request",
	ErrorDescription: "Could not proccess approval request",
	Abort:            true,
}

var AccessDeniedError = &OAuthError{
	Err:              "access_denied",
	ErrorDescription: "The user or the authorization server denied the request",
	Abort:            false,
}

var InvalidClientError = &OAuthError{
	Err:              "invalid_request",
	ErrorDescription: "Invalid client details",
	Abort:            true,
}

var UnsupportedResponseTypeError = &OAuthError{
	Err:              "unsupported_response_type",
	ErrorDescription: "Unsupported response type",
	Abort:            false,
}

var InvalidScopeError = &OAuthError{
	Err:              "invalid_scope",
	ErrorDescription: "Requested scopes are not valid",
	Abort:            false,
}
