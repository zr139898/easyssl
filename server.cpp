#include "easyssl.h"
#include <iostream>
using namespace std;

#define VERSION "Compatible_server"
#define SERVERCERT "server.pem"
#define SERVERPRK "serverprk.pem"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define VERIFY_MODE "AUTH_REQUIRE"
#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define PORT "6001"

void THREAD_CC server_thread(void * arg) {
    EasySSL * ssl = (EasySSL *)arg;
#ifndef WIN32
    pthread_detach(pthread_self());
#endif
    ssl->AcceptSSLConnection();
    fprintf(stderr, "Connection opened.\n");
    
    int err, nread;
    char buf[80];
    
    do {
        for (nread = 0; nread < sizeof(buf); nread += err) {
            err = ssl->Read(buf + nread, sizeof(buf) - nread);
            if (err <= 0)
                break;
        }
        fprintf(stderr, "%s", buf);
    } while (err > 0);
    if ((ssl->GetShutdown() & SSL_RECEIVED_SHUTDOWN) ? 1 : 0)
        ssl->Shutdown();
    else
        ssl->Clear();
    fprintf(stderr, "Connection closed.\n");
    delete ssl;
    ERR_remove_state(0);
#ifdef WIN32
    _endthread();
#endif
}

int main(void) {
    EasySSL_CTX::InitEasySSL();
    EasySSL_CTX ctx;

    ctx.LoadConf("server.cnf");
    // ctx.SetVersion(VERSION);
    // ctx.SetVerifyMode(VERIFY_MODE);
    // ctx.SetVerifyDepth(4);
    // ctx.SetCipherSuite(CIPHER_LIST);
    // ctx.LoadCACertLocations(CAFILE, CADIR);
    // ctx.LoadOwnCert(SERVERCERT);
    // ctx.LoadOwnPrivateKey(SERVERPRK);

    ctx.CreateListenSocket(const_cast<char *>(PORT));
    
    THREAD_TYPE tid;
    EasySSL * easyssl;
    
    while (1) {
        easyssl = ctx.AcceptSocketConnection();
        THREAD_CREATE(tid, server_thread, easyssl);
    }
    return 0;
}

