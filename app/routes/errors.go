package routes

import (
	"encoding/json"
	"net/http"
	"net/url"
	"oauth2-server/app/domain"
)

func proccessError(w http.ResponseWriter, r *http.Request, errorRedirectURL, state string, err *domain.OAuthError) {
	if err.Abort {
		renderError(w, r, err)
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

func renderError(w http.ResponseWriter, r *http.Request, err *domain.OAuthError) {
	jsonBody, _ := json.Marshal(err)
	http.Error(w, string(jsonBody), http.StatusUnauthorized)
}
