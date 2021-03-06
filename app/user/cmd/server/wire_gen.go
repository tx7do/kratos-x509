// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package main

import (
	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"kratos-x509/app/user/internal/conf"
	"kratos-x509/app/user/internal/server"
	"kratos-x509/app/user/internal/service"
)

// Injectors from wire.go:

// initApp init kratos application.
func initApp(confServer *conf.Server, registry *conf.Registry, logger log.Logger) (*kratos.App, func(), error) {
	userService := service.NewUserService(logger)
	grpcServer := server.NewGRPCServer(confServer, logger, userService)
	registrar := server.NewRegistrar(registry)
	app := newApp(logger, grpcServer, registrar)
	return app, func() {
	}, nil
}
