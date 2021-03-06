// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package main

import (
	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"kratos-x509/app/admin/internal/conf"
	"kratos-x509/app/admin/internal/data"
	"kratos-x509/app/admin/internal/server"
	"kratos-x509/app/admin/internal/service"
)

// Injectors from wire.go:

// initApp init kratos application.
func initApp(confServer *conf.Server, registry *conf.Registry, logger log.Logger) (*kratos.App, func(), error) {
	discovery := data.NewDiscovery(registry)
	userServiceClient := data.NewUserServiceClient(discovery)
	adminService := service.NewAdminService(userServiceClient, logger)
	httpServer := server.NewHTTPServer(confServer, logger, adminService)
	grpcServer := server.NewGRPCServer(confServer, logger, adminService)
	registrar := server.NewRegistrar(registry)
	app := newApp(logger, httpServer, grpcServer, registrar)
	return app, func() {
	}, nil
}
