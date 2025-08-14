#!/bin/bash

echo "Hello"

# Client
openssl genrsa -out client_3day.key 2048
openssl req -new -out client_3day.csr -key client_3day.key -subj "/C=CN/ST=Shanxi/L=Xian/O=EXEC/OU=DS/CN=client_3day_ip"
openssl x509 -req -in client_3day.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client_3day.crt -days 3
openssl rsa -in client_3day.key -out client_3day.key
