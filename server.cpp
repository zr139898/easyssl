#include "easyssl.h"
#include <iostream>
using namespace std;

#define VERSION "Compatible"
#define SERVERCERT "server.pem"
#define SERVERPRK "serverprk.pem"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define VERIFY_MODE SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT
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
    EasySSL_CTX::Init_EasySSL();
    EasySSL_CTX ctx(VERSION);
    ctx.LoadCACertLocations(CAFILE, CADIR);
    ctx.LoadOwnCert(SERVERCERT);
    ctx.LoadOwnPrivateKey(SERVERPRK);
    ctx.SetVerifyMode(VERIFY_MODE);
    ctx.SetVerifyDepth(4);
    ctx.SetOptions(SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
    ctx.SetTmpDHCallback();
    ctx.SetCipherSuite(CIPHER_LIST);
    
    THREAD_TYPE tid;
    SSL * ssl;
    BIO * client;
    EasySSL * easyssl;
    //BIO * acc = BIO_new_accept(const_cast<char *>(PORT));
    //if (BIO_do_accept(acc) <= 0)
    //  int_error("Error binding server socket");
    ctx.CreateListenSocket(const_cast<char *>(PORT));
    while (1) {
        //if (BIO_do_accept(acc) <= 0)
        //  int_error("Error accepting connection");
        //client = BIO_pop(acc);
        //if (!(ssl = SSL_new(ctx.ctx_)))
        //  int_error("Error creating SSL context");
        //SSL_set_accept_state(ssl);
        //SSL_set_bio(ssl, client, client);
        easyssl = ctx.AcceptSocketConnection();
        THREAD_CREATE(tid, server_thread, easyssl);
    }
    return 0;
}

