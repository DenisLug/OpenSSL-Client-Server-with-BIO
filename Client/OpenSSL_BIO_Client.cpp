/*
 * OpenSSL_BIO_Client.cpp
 *
 *  Created on: 29.11.2018
 *  Author: Denis Lugowski
 */

#include "OpenSSL_BIO_Client.h"

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

OpenSSL_BIO_Client::OpenSSL_BIO_Client() {}

OpenSSL_BIO_Client::~OpenSSL_BIO_Client() {}

void OpenSSL_BIO_Client::createSocket()
{
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (clientSocket < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
}

void OpenSSL_BIO_Client::connectToServer(int port)
{
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    if (connect(clientSocket, (struct sockaddr*) &serverAddress, sizeof(serverAddress)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");

    // ====== Begin SSL handling ====== //
    doSSLHandshake();
    // ====== End SSL handling ====== //
}

void OpenSSL_BIO_Client::doSSLHandshake()
{
    char buffer[BUFFER_SIZE] = { 0 };

    while (!SSL_is_init_finished(ssl)) {
        SSL_do_handshake(ssl);

        int bytesToWrite = BIO_read(writeBIO, buffer, BUFFER_SIZE);

        if (bytesToWrite > 0) {
            printf("Host has %d bytes encrypted data to send\n", bytesToWrite);
            write(clientSocket, buffer, bytesToWrite);
        }
        else {
            int receivedBytes = read(clientSocket, buffer, BUFFER_SIZE);
            if (receivedBytes > 0) {
                printf("Host has received %d bytes data\n", receivedBytes);
                BIO_write(readBIO, buffer, receivedBytes);
            }
        }
    }

    printf("Host SSL handshake done!\n");
}

void OpenSSL_BIO_Client::writeToSocket()
{
    char buffer[BUFFER_SIZE] = { 0 };

    int msgSize = read(STDIN_FILENO, buffer, sizeof(buffer));
    buffer[msgSize - 1] = '\0';

    if (msgSize > 0) {
        // Note: No need to do BIO_write(readBIO) before, SSL_write takes
        // buffer with unencrypted data directly.
        // See: https://www.openssl.org/docs/man1.1.1/man3/SSL_write.html
        SSL_write(ssl, buffer, msgSize);

        int bytesToWrite = BIO_read(writeBIO, buffer, sizeof(buffer));

        if (bytesToWrite > 0) {
            printf("Host has %d bytes encrypted data to send\n", bytesToWrite);
            write(clientSocket, buffer, bytesToWrite);
        }
    }
}

void OpenSSL_BIO_Client::initOpenSSL()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    context = createContext();
    configureContext(context);

    ssl = SSL_new(context);
    readBIO = BIO_new(BIO_s_mem());
    writeBIO = BIO_new(BIO_s_mem());

    SSL_set_bio(ssl, readBIO, writeBIO);
    SSL_set_connect_state(ssl); // Client
}

SSL_CTX* OpenSSL_BIO_Client::createContext()
{
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    const long flags = SSL_EXT_TLS1_3_ONLY;
    SSL_CTX_set_options(ctx, flags);

    return ctx;
}

void OpenSSL_BIO_Client::configureContext(SSL_CTX* ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void OpenSSL_BIO_Client::closeSocket()
{
    close(clientSocket);
}

void OpenSSL_BIO_Client::cleanupOpenSSL()
{
    SSL_CTX_free(context);
    EVP_cleanup();
}

