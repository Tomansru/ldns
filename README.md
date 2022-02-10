# LDNS

Router for local traffic based on DNS records

```
openssl genrsa -aes256 -out rootCA.key 4096
openssl req -new -x509 -nodes -days 365000 -sha256 -extensions v3_ca -key rootCA.key -out rootCA.crt
```

```
openssl genrsa -out mitm.key 2048
openssl req -new sha384 -addext "subjectAltName = DNS:*" -key mitm.key -out mitm.csr
openssl x509 -req -in mitm.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out mitm.crt -days 365000 -sha384
```
