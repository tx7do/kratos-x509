package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http"
	GRPC "google.golang.org/grpc"
	"io/ioutil"
	"log"
	"path/filepath"

	v1 "kratos-x509/api/admin/v1"
)

// newCertPool creates x509 certPool with provided CA file
func newCertPool(CAFile string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	pemByte, err := ioutil.ReadFile(CAFile)
	if err != nil {
		return nil, err
	}

	//for {
	//	var block *pem.Block
	//	block, pemByte = pem.Decode(pemByte)
	//	if block == nil {
	//		return certPool, nil
	//	}
	//	cert, err := x509.ParseCertificate(block.Bytes)
	//	if err != nil {
	//		return nil, err
	//	}
	//	certPool.AddCert(cert)
	//}

	if !certPool.AppendCertsFromPEM(pemByte) {
		return nil, fmt.Errorf("can't add CA cert")
	}
	return certPool, nil
}

func NewTlsConfig(keyFile, certFile, caFile string) *tls.Config {
	var cfg tls.Config
	cfg.InsecureSkipVerify = true

	if caFile != "" {
		cp, err := newCertPool(caFile)
		if err != nil {
			return nil
		}

		cfg.RootCAs = cp
	}

	if keyFile == "" || certFile == "" {
		return &cfg
	}

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil
	}

	cfg.Certificates = []tls.Certificate{tlsCert}

	return &cfg
}

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
	callHTTP("https://127.0.0.1:8000", NewTlsConfig(dir+"/client.key", dir+"/client.crt", dir+"/ca.crt"))
	callGRPC("127.0.0.1:9000", NewTlsConfig(dir+"/client.key", dir+"/client.crt", dir+"/ca.crt"))
}
