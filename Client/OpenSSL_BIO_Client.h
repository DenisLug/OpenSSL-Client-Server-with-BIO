/*
 * OpenSSL_BIO_Client.h
 *
 *  Created on: 29.11.2018
 *  Author: Denis Lugowski
 */

#ifndef OpenSSL_BIO_Client_H_
#define OpenSSL_BIO_Client_H_

#include <netinet/in.h>

struct ssl_ctx_st;
struct ssl_st;
struct bio_st;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct bio_st BIO;

class OpenSSL_BIO_Client {
public:
	OpenSSL_BIO_Client();
	virtual ~OpenSSL_BIO_Client();

	// Socket functions
	void createSocket();
	void connectToServer(int port);
	void writeToSocket();
	void closeSocket();

	// OpenSSL_BIO_Client functions
	void initOpenSSL();
	void cleanupOpenSSL();
	SSL_CTX* createContext();
	void configureContext(SSL_CTX* ctx);
	void doSSLHandshake();

private:
	int clientSocket;
	struct sockaddr_in serverAddress;

	SSL* ssl;
	SSL_CTX* context;
	BIO* readBIO;
	BIO* writeBIO;

	const int BUFFER_SIZE = 4096;
	const char* CERT_FILE = "/home/denis/workspace_cpp/OpenSSL/assets/cert.pem";
	const char* KEY_FILE = "/home/denis/workspace_cpp/OpenSSL/assets/key.pem";
};

#endif /* OpenSSL_BIO_Client_H_ */
