#!/bin/bash

openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -subj "/CN=ca-mnsec-proxy" -days 10000 -out ca.crt
openssl genrsa -out server.key 2048
cat > server-csr.conf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = BR
ST = Bahia
L = Salvador
O = UFBA
OU = HackInSDN
CN = mnsec-proxy-service.hackinsdn.svc.cnacv5

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = kubernetesmnsec-proxy.hackinsdn.svc.cnacv5
IP.1 = 10.50.252.231

[ v3_ext ]
authorityKeyIdentifier=keyid,issuer:always
basicConstraints=CA:FALSE
keyUsage=keyEncipherment,dataEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=@alt_names
EOF

openssl req -new -key server.key -out server.csr -config server-csr.conf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 10000 -extensions v3_ext -extfile server-csr.conf -sha256
openssl dhparam -out dhparams.pem 2048
cat server.crt ca.crt > server-chain.crt

