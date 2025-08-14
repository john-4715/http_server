#!/bin/bash

echo "Hello"

# Client
openssl genrsa -out client_30day.key 2048
openssl req -new -out client_30day.csr -key client_30day.key -subj "/C=CN/ST=Shanxi/L=Xian/O=EXEC/OU=DS/CN=client_30day_ip"
openssl x509 -req -in client_30day.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client_30day.crt -days 30
openssl rsa -in client_30day.key -out client_30day.key
