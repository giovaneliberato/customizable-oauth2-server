package infra

import "github.com/go-chi/httplog"

var LOGGER = httplog.NewLogger("httplog-example", httplog.Options{})
