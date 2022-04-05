:: 生成CA的私钥和证书
echo Generate the ca certificate
openssl genrsa -out ../certs/ca.key 4096
openssl req -x509 -sha256 -new -nodes -key ../certs/ca.key -days 3650 -subj "/C=CN/O=VMware/CN=Root CA" -extensions v3_ca -out ../certs/ca.crt

:: 生成服务端的私钥和证书
echo generating server certificate
openssl genrsa -out ../certs/server.key 2048
openssl req -new -subj "/C=CN/O=VMware/CN=host.docker.internal" -key ../certs/server.key -out server_signing_req.csr
openssl x509 -req -days 365 -in server_signing_req.csr -CA ../certs/ca.crt -CAkey ../certs/ca.key -CAcreateserial -out ../certs/server.crt
del server_signing_req.csr

:: 生成客户端的私钥和证书
echo generating client certificate
openssl genrsa -out ../certs/client.key 2048
openssl req -new -subj "/C=CN/O=VMware/CN=host.docker.internal" -key ../certs/client.key -out client_signing_req.csr
openssl x509 -req -days 365 -in client_signing_req.csr -CA ../certs/ca.crt -CAkey ../certs/ca.key -CAcreateserial -out ../certs/client.crt
del client_signing_req.csr

:: 验证证书
openssl verify -CAfile ../certs/ca.crt ../certs/server.crt
openssl verify -CAfile ../certs/ca.crt ../certs/client.crt

pause