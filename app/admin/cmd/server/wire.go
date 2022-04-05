//go:build wireinject
// +build wireinject

// The build tag makes sure the stub is not built in the final build.

package main

import (
	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/wire"

	"kratos-x509/app/admin/internal/conf"
	"kratos-x509/app/admin/internal/data"
	"kratos-x509/app/admin/internal/server"
	"kratos-x509/app/admin/internal/service"
)

// initApp init kratos application.
func initApp(*conf.Server, *conf.Registry, log.Logger) (*kratos.App, func(), error) {
	panic(wire.Build(server.ProviderSet, service.ProviderSet, data.ProviderSet, newApp))
}
