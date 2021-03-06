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
    ssl->SSLAccept();
    fprintf(stderr, "Connection opened.\n");
    
    int len, len_read;
    char buf[80];
    
    do {
        for (len_read = 0; len_read < sizeof(buf); len_read += len) {
            len = ssl->Read(buf + len_read, sizeof(buf) - len_read);
            if (len <= 0)
                break;
            printf("%s", buf);
        }
    } while (len > 0);
    
    ssl->Shutdown();
    
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
    // ctx.SetAuthentication(VERIFY_MODE);
    // ctx.SetCipherSuite(CIPHER_LIST);
    // ctx.LoadCACertLocations(CAFILE, CADIR);
    // ctx.LoadOwnCert(SERVERCERT);
    // ctx.LoadOwnPrivateKey(SERVERPRK);
    // ctx.SetCRLFile(CRLFILE);

    ctx.CreateListenSocket(const_cast<char *>(PORT));
    
    THREAD_TYPE tid;
    EasySSL * easyssl;
    
    while (1) {
        easyssl = ctx.AcceptSocketConnection();
        THREAD_CREATE(tid, server_thread, easyssl);
    }
    EasySSL_CTX::FreeEasySSL();
    return 0;
}

