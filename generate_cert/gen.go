package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	serialNumber *big.Int
	privateKey   interface{}
)

func generateTemplate(privateKeyType, host, dir string, isCA, isClient, isServer bool) {
	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		BasicConstraintsValid: true,
	}

	// 处理路径
	dir = processDir(dir)
	log.Println("dir:", dir)

	// 序列数
	template.SerialNumber = generateSerialNumber()

	// 生效时间，过期时间
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().AddDate(10, 0, 0)

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// 典型用法是用于叶子证书中的公钥的使用目的。它包括一系列的OID，每一个都指定一种用途。比如{ id-pkix 3 1 } 表示用于服务器端的TLS/SSL连接，而{ id-pkix 3 4 }用于email的安全操作。
	// 通常情况下，一份证书有多个限制用途的扩展时，所有限制条件都应该满足才可以使用。RFC 5280里有对一个同时含有keyUsage和extendedKeyUsage的证书的例子，这样的证书只能用在两个扩展中都指定了的用途。比如网络安全服务决定证书用途时会同时对这两个扩展进行判断
	if isClient {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if isServer {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	// 创建私钥
	if privateKey == nil {
		privateKey = generatePrivateKey(privateKeyType)
	}

	// 指定了这份证书包含的公钥可以执行的密码操作。作为一个例子，它可以指定只能用于签名，而不能用来进行加密操作。
	keyUsage := x509.KeyUsageDigitalSignature
	if _, isRSA := privateKey.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(privateKey), privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certFileName := "cert.crt"
	keyFileName := "cert.key"
	if isCA {
		certFileName = "ca.crt"
		keyFileName = "ca.key"
	}
	if isClient && isServer {
		certFileName = "cert.crt"
		keyFileName = "cert.key"
	} else if isClient {
		certFileName = "client.crt"
		keyFileName = "client.key"
	} else if isServer {
		certFileName = "server.crt"
		keyFileName = "server.key"
	}
	certFileName = dir + certFileName
	keyFileName = dir + keyFileName

	certOut, err := os.Create(certFileName)
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %v", err)
	}
	log.Print("wrote cert.pem\n")

	keyOut, err := os.OpenFile(keyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
		return
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %v", err)
	}
	log.Print("wrote key.pem\n")
}

func processDir(dir string) string {
	if runtime.GOOS == "windows" {
		dir = filepath.FromSlash(dir)
	} else {
		dir = filepath.ToSlash(dir)
	}
	// 必须要绝对路径
	if filepath.IsAbs(dir) == false {
		dir, _ = filepath.Abs(dir)
	}
	if runtime.GOOS == "windows" {
		dir = filepath.FromSlash(dir) + "\\"
	} else {
		dir = filepath.ToSlash(dir) + "/"
	}
	return dir
}

func generateSerialNumber() *big.Int {
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		_serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			log.Fatalf("Failed to generate serial number: %v", err)
			return nil
		}
		serialNumber = _serialNumber
		return _serialNumber
	} else {
		return serialNumber
	}
}

func generateRsaPrivateKey() *rsa.PrivateKey {
	rsaBits := 2048
	privateKey, _ := rsa.GenerateKey(rand.Reader, rsaBits)
	return privateKey
}

func generateED25519PrivateKey() *ed25519.PrivateKey {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	return &privateKey
}

func generateECDSAPrivateKey(ecdsaCurve string) *ecdsa.PrivateKey {
	var privateKey *ecdsa.PrivateKey
	switch ecdsaCurve {
	case "P224":
		privateKey, _ = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		privateKey, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		privateKey, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	}
	return privateKey
}

func generatePrivateKey(privateKeyType string) interface{} {
	switch privateKeyType {
	case "RSA":
		return generateRsaPrivateKey()
	case "ED25519":
		return generateED25519PrivateKey()
	case "P224", "P256", "P384", "P521":
		return generateECDSAPrivateKey(privateKeyType)
	default:
		log.Fatalf("Unrecognized private key type: %q", privateKeyType)
		return nil
	}
}

func publicKey(privateKey interface{}) interface{} {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func generate() {
	privateKeyType := "RSA"
	host := "127.0.0.1"

	// CA
	generateTemplate(privateKeyType, host, "./certs/", true, false, false)
	// client
	generateTemplate(privateKeyType, host, "./certs/", true, true, false)
	// server
	generateTemplate(privateKeyType, host, "./certs/", true, false, true)
}

func main() {
	generate()
}
