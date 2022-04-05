package data

import (
	"context"
	"fmt"
	"github.com/go-kratos/kratos/contrib/registry/consul/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/tracing"
	"github.com/go-kratos/kratos/v2/registry"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/google/wire"
	consulAPI "github.com/hashicorp/consul/api"
	userV1 "kratos-x509/api/user/v1"
	"kratos-x509/app/admin/internal/conf"
	"kratos-x509/pkg/util/bootstrap"
	"path/filepath"
	"time"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(
	NewData,
	NewDiscovery,
	NewUserServiceClient,
)

// Data .
type Data struct {
	log  *log.Helper
	user userV1.UserServiceClient
}

// NewData .
func NewData(logger log.Logger, user userV1.UserServiceClient) (*Data, func(), error) {
	l := log.NewHelper(log.With(logger, "module", "data/user-service"))

	d := &Data{
		log:  l,
		user: user,
	}

	return d, func() {
	}, nil
}

// NewDiscovery 创建服务发现客户端
func NewDiscovery(conf *conf.Registry) registry.Discovery {
	c := consulAPI.DefaultConfig()
	c.Address = conf.Consul.Address
	c.Scheme = conf.Consul.Scheme
	cli, err := consulAPI.NewClient(c)
	if err != nil {
		panic(err)
	}
	r := consul.New(cli, consul.WithHealthCheck(conf.Consul.HealthCheck))
	return r
}

func NewUserServiceClient(r registry.Discovery) userV1.UserServiceClient {
	dir, _ := filepath.Abs("../../../../certs/")
	fmt.Println("dir: ", dir)

	conn, err := grpc.DialInsecure(
		context.Background(),
		grpc.WithEndpoint("discovery:///kratos.x509.user"),
		grpc.WithDiscovery(r),
		grpc.WithMiddleware(
			tracing.Client(),
			recovery.Recovery(),
		),
		grpc.WithTimeout(2*time.Second),
		grpc.WithTLSConfig(bootstrap.NewClientTlsConfig("", "", dir+"/ca.crt")),
	)
	if err != nil {
		panic(err)
	}
	return userV1.NewUserServiceClient(conn)
}
