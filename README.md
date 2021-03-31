
![](_docs/img/oauth-logo.png)
# OAuth2 server - Ready for customization!

This repository implements a **fully-compliant OAuth2 server** following the [RFC-6749](https://tools.ietf.org/html/rfc6749). It is framework and infrastructure agnostic. 

The goal of this project is to provide a scaffold for the ones who need to provide OAuth integration but already have their login systems in place.

Most famous web frameworks that provide some kind of user management have OAuth plugins available. However, most systems nowadays are sofisticated enough to implement their own usser session and management.

With this scenario in mind, this projects "wraps" your existing login systems with the OAuth2.0 framework. Almost everything is taken care of already (request and validation, context keeping between requests, response and errors) and you just need to adapt it to your reality and deploy to your infrastructure.

<br>
<br>

[![try-it](https://img.shields.io/badge/See%20it%20in%20Action!--blue)](http://golang.org)


[Getting Started](_docs/getting_started.md) • [Customizing](_docs/customizing.md) 

**Note:** This is not a library. There might be breaking changes in the future as the protocol evolves. Consider this project a scaffold for your own implementation.

__________________________
[![Build Status](https://travis-ci.com/giovaneliberato/customizable-oauth2-server.svg?branch=main)](https://travis-ci.com/giovaneliberato/customizable-oauth2-server) [![made-with-Go](https://img.shields.io/badge/Made%20with-Go-1f425f.svg)](http://golang.org) [![GitHub license](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/Naereen/StrapDown.js/blob/master/LICENSE) [![Go Report Card](https://goreportcard.com/badge/github.com/giovaneliberato/your-oauth2-server-here)](https://goreportcard.com/report/github.com/giovaneliberato/your-oauth2-server-here)




