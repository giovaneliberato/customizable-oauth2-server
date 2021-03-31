# Customizing


## Login & Consent page
The first integration required by the oauth2-server is a login page. The oauth2-server is going to redirect authorization requests for this page with the client information.


This endpoint will receive the following parameters as query string:

| name              | type        | description  |
| :---------------: | :---------: | :----------- |
| client_name       | string      | The human-friendly client name. Can be used to display the client information to the user |
| client_id         | string      | The client identificator. |
| requested_scopes  | []strings   | A list of the scopes requested by the client. This must be displayed for the user. |
| signed_context    | string      | A signed JWT containing all the context information needed to finish the authorization. This value needs to be returned exactly as it is to the oauth2-server, otherwise the authorization will fail.|


### Show Client Details and Requested Scopes
After the user sign in into your application, you must show the consent page.  
See [example](https://www.oauth.com/oauth2-servers/authorization/the-authorization-interface).

The user can either approve or deny the authorization.

### Redirect to oauth2-server
In both cases, the oauth2-server should be notified (and therefore notify the client application) about the result.

Redirect the request to `<oauth2-server-base-url>/oauth2/approval-authorization` with the following parameters as query string:


| name                | type        | description  |
| :-----------------: | :---------: | :----------- |
| approved            | boolean     | Whether the user approved or not. |
| signed_context      | string      | The signed_context received by the login page |
| authorization_code  | string      | (If approved=true) An authorization code that can later be exchanged by an access token.|



## HTTP Gateway
In order to integrate with your systems, you need to implement an HTTP client for your own endpoints that acommodates these two use cases:

- Exchange Authorization Code for AccessToken
- Refresh Access Token

These changes need to be made at `app/domain/token/gateway.go`.


## Config file
In the file `app/config.yaml` you will need to edit the values to reflect your application.



## Database
You need to implement the database layer to make client management persistent. The file to be changed is `app/domain/client/repository.go`

## Monitoring
There is a simple logging mechanism in place under `app/domain/(authorization|token)/monitoring.go.`

This can be either incremented, changed or removed.


## Cache
tdb

