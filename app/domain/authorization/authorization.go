package authorization

// Authorization representing the data sent in the first request of the protocol
type AuthorizationRequest struct {
	ClientID    string
	GrantType   string
	RedirectURI string
	Scope       []string
	State       string
}
