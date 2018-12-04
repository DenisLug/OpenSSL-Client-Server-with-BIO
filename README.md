# OpenSSL client/server application with I/O stream abstraction (BIO)

This application shows how to create an OpenSSL TLS connection over TCP sockets using memory BIOs. 

## Prerequisites
1. Create a certificate and key file with this command:
```
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365
```
2. Change the paths of the certificate and key file in OpenSSL_BIO_Server/Client.h.

## Start
1. Build & run server.
2. Build & run client.
3. When TLS handshake is finished try sending a message by typing into the console of the client.

## Other useful examples
- https://github.com/darrenjs/openssl_examples
- http://www.roxlu.com/2014/042/using-openssl-with-memory-bios
- http://blog.davidwolinsky.com/2009/10/memory-bios-and-openssl.html