package routes

import (
	"encoding/json"
	"net/http"
	"net/url"
	"oauth2-server/domain"
)

func proccessError(w http.ResponseWriter, r *http.Request, errorRedirectURL, state string, err *domain.OAuthError) {
	if err.Abort {
		renderErrorWithStatus(w, r, err, http.StatusUnauthorized)
	} else {
		redirectError(w, r, errorRedirectURL, state, err)
	}
}

func redirectError(w http.ResponseWriter, r *http.Request, errorRedirectURL, state string, err *domain.OAuthError) {
	qs := url.Values{}
	qs.Add("error", err.Err)
	qs.Add("error_description", err.ErrorDescription)
	qs.Add("state", state)
	errorRedirectURL += "?" + qs.Encode()
	http.Redirect(w, r, errorRedirectURL, http.StatusFound)
}

func renderErrorWithStatus(w http.ResponseWriter, r *http.Request, err *domain.OAuthError, status int) {
	jsonBody, _ := json.Marshal(err)
	http.Error(w, string(jsonBody), status)
}
