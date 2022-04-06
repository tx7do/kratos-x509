package main

import (
	"context"
	"crypto/tls"
	"kratos-x509/pkg/util/bootstrap"
	"log"
	"path/filepath"

	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http"
	GRPC "google.golang.org/grpc"

	v1 "kratos-x509/api/admin/v1"
)

func callHTTP(endpoint string, tlsConf *tls.Config) {
	conn, err := http.NewClient(
		context.Background(),
		http.WithEndpoint(endpoint),
		http.WithTLSConfig(tlsConf),
	)
	if err != nil {
		panic(err)
	}
	defer func(conn *http.Client) {
		err := conn.Close()
		if err != nil {
			panic(err)
		}
	}(conn)

	client := v1.NewAdminServiceHTTPClient(conn)

	{
		reply, err := client.Register(context.Background(), &v1.RegisterReq{Username: "kratos"})
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("[http] User Register Result: %v\n", reply)
	}
	{
		reply, err := client.GetUser(context.Background(), nil)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("[http] Get User Result: %v\n", reply)
	}

	//{
	//	reply, err := client.Login(context.Background(), &v1.LoginReq{UserName: "kratos"})
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	log.Printf("[http] User Logon Result: %v\n", reply)
	//}
}

func callGRPC(endpoint string, tlsConf *tls.Config) {
	conn, err := grpc.Dial(
		context.Background(),
		grpc.WithEndpoint(endpoint),
		grpc.WithTLSConfig(tlsConf),
	)
	if err != nil {
		panic(err)
	}
	defer func(conn *GRPC.ClientConn) {
		err := conn.Close()
		if err != nil {
			panic(err)
		}
	}(conn)

	client := v1.NewAdminServiceClient(conn)

	reply, err := client.Register(context.Background(), &v1.RegisterReq{Username: "kratos"})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[grpc] User Register Result: %v\n", reply)

	//reply, err := client.Login(context.Background(), &v1.LoginReq{UserName: "kratos"})
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Printf("[grpc] User Logon Result: %v\n", reply)
}

func main() {
	dir, _ := filepath.Abs("./certs/")
	log.Printf("dir: %s\n", dir)
	//callHTTP("https://host.docker.internal:8000", bootstrap.NewClientTlsConfig(dir+"/client.key", dir+"/client.crt", dir+"/ca.crt"))
	callHTTP("https://host.docker.internal:8000", bootstrap.NewClientTlsConfig("", "", ""))
	callGRPC("127.0.0.1:9000", bootstrap.NewClientTlsConfig(dir+"/client.key", dir+"/client.crt", dir+"/ca.crt"))
}
