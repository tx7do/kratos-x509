package server

import (
	"fmt"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/tracing"
	"github.com/go-kratos/kratos/v2/transport/http"
	"github.com/go-kratos/swagger-api/openapiv2"
	"github.com/gorilla/handlers"
	"kratos-x509/api/admin/v1"
	"kratos-x509/app/admin/internal/conf"
	"kratos-x509/pkg/util/bootstrap"
	"path/filepath"

	"kratos-x509/app/admin/internal/service"
)

// NewMiddleware 创建中间件
func NewMiddleware(logger log.Logger) http.ServerOption {
	return http.Middleware(
		recovery.Recovery(),
		tracing.Server(),
		logging.Server(logger),
	)
}

// NewHTTPServer new an HTTP server.
func NewHTTPServer(c *conf.Server, logger log.Logger, s *service.AdminService) *http.Server {
	dir, _ := filepath.Abs("../../../../certs/")
	fmt.Println("dir: ", dir)

	var opts = []http.ServerOption{
		NewMiddleware(logger),
		http.Filter(handlers.CORS(
			handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"}),
			handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}),
			handlers.AllowedOrigins([]string{"*"}),
		)),
		http.TLSConfig(bootstrap.NewServerTlsConfig(dir+"/server.key", dir+"/server.crt", dir+"/ca.crt")),
	}
	if c.Http.Network != "" {
		opts = append(opts, http.Network(c.Http.Network))
	}
	if c.Http.Addr != "" {
		opts = append(opts, http.Address(c.Http.Addr))
	}
	if c.Http.Timeout != nil {
		opts = append(opts, http.Timeout(c.Http.Timeout.AsDuration()))
	}

	srv := http.NewServer(opts...)

	h := openapiv2.NewHandler()
	srv.HandlePrefix("/q/", h)

	v1.RegisterAdminServiceHTTPServer(srv, s)
	return srv
}
