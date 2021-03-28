package routes_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"oauth2-server/app/routes"
	"oauth2-server/app/test"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateClientError(t *testing.T) {
	var server = test.TestServerFor(routes.ClienRouter)

	clientData := map[string]interface{}{
		"id":                     "",
		"secret":                 "secret",
		"allowed_redirect_urls":  []string{"http://test.com/callback"},
		"allowed_response_types": []string{"code"},
		"allowed_scopes":         []string{"profile"},
	}

	jsonValue, _ := json.Marshal(clientData)
	req, _ := http.NewRequest("POST", server.URL+"/oauth2/client", bytes.NewBuffer(jsonValue))

	resp, _ := httpClient().Do(req)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateClientSuccess(t *testing.T) {
	var server = test.TestServerFor(routes.ClienRouter)

	clientData := map[string]interface{}{
		"id":                     "new-test-client",
		"name":                   "Test Third Part App",
		"secret":                 "secret",
		"allowed_redirect_urls":  []string{"http://test.com/callback"},
		"allowed_response_types": []string{"code"},
		"allowed_scopes":         []string{"profile"},
	}

	jsonValue, _ := json.Marshal(clientData)
	req, _ := http.NewRequest("POST", server.URL+"/oauth2/client", bytes.NewBuffer(jsonValue))

	resp, _ := httpClient().Do(req)

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}
