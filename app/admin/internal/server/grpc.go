package server

import (
	"fmt"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/tracing"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"kratos-x509/api/admin/v1"
	"kratos-x509/app/admin/internal/conf"
	"kratos-x509/app/admin/internal/service"
	"kratos-x509/pkg/util/bootstrap"
	"path/filepath"
)

// NewGRPCServer new a gRPC server.
func NewGRPCServer(c *conf.Server, logger log.Logger, s *service.AdminService) *grpc.Server {
	dir, _ := filepath.Abs("../../../../certs/")
	fmt.Println("dir: ", dir)

	var opts = []grpc.ServerOption{
		grpc.Middleware(
			recovery.Recovery(),
			tracing.Server(),
			logging.Server(logger),
		),
		grpc.TLSConfig(bootstrap.NewServerTlsConfig(dir+"/server.key", dir+"/server.crt", dir+"/ca.crt")),
	}
	if c.Grpc.Network != "" {
		opts = append(opts, grpc.Network(c.Grpc.Network))
	}
	if c.Grpc.Addr != "" {
		opts = append(opts, grpc.Address(c.Grpc.Addr))
	}
	if c.Grpc.Timeout != nil {
		opts = append(opts, grpc.Timeout(c.Grpc.Timeout.AsDuration()))
	}
	srv := grpc.NewServer(opts...)
	v1.RegisterAdminServiceServer(srv, s)
	return srv
}
