package authorization

import (
	"goauth-extension/app/domain/client"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/google/uuid"
)

// Authorization representing the data sent in the first request of the protocol
type AuthorizationRequest struct {
	ClientID    string
	GrantType   string
	RedirectURI string
	Scope       []string
	State       string
}

type ConsentContext struct {
	ClientID                   string
	RequestedScopes            []string
	SignedAuthorizationRequest string
}

type Service interface {
	Authorize(AuthorizationRequest) (ConsentContext, *ValidationError)
}

type service struct {
	client client.Service
}

func NewService(client client.Service) Service {
	return &service{
		client: client,
	}
}

func (s *service) Authorize(request AuthorizationRequest) (ConsentContext, *ValidationError) {
	client := s.client.GetByID(request.ClientID)

	err := Validate(client, request)
	if err != nil {
		return ConsentContext{}, err
	}

	ctx := ConsentContext{
		ClientID:                   client.ID,
		RequestedScopes:            request.Scope,
		SignedAuthorizationRequest: signAndEncode(request),
	}

	return ctx, nil
}

func signAndEncode(req AuthorizationRequest) string {
	token := jwt.New(jwt.GetSigningMethod("HS256"))

	token.Claims = jwt.MapClaims{
		"client_id":    req.ClientID,
		"state":        req.State,
		"scopes":       req.Scope,
		"redirect_uri": req.RedirectURI,
		"nounce":       uuid.NewString(), // here to avoid replay attacks
	}

	tokenString, _ := token.SignedString("signing-key")
	return tokenString
}
