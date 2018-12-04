/*
 * Main.cpp
 *
 *  Created on: 29.11.2018
 *  Author: Denis Lugowski
 */

#include <stdio.h>
#include "OpenSSL_BIO_Server.h"

int main(int argc, char **argv) {
	OpenSSL_BIO_Server server;

	server.createSocket(8000);
	server.initOpenSSL();
	server.waitForIncomingConnection();

	while (1) {
		char* msg = server.readFromSocket();
		printf("Message: %s\n", msg);
		delete(msg);
	}

	server.closeSocket();
	server.cleanupOpenSSL();

}


