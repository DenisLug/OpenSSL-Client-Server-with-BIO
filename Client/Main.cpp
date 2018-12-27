/*
 * Main.cpp
 *
 *  Created on: 29.11.2018
 *  Author: Denis Lugowski
 */

#include <stdio.h>
#include "OpenSSL_BIO_Client.h"

int main(int argc, char **argv)
{
    OpenSSL_BIO_Client client;

    client.createSocket();
    client.initOpenSSL();

    client.connectToServer(8000);

    while (1) {
        client.writeToSocket();
    }

    client.closeSocket();
    client.cleanupOpenSSL();
}
