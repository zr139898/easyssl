#include "easyssl.h"
#include <iostream>
using namespace std;

#define VERSION "Compatible"
#define CLIENTCERT "client.pem"
#define CLIENTPRK "clientprk.pem"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define VERIFY_MODE SSL_VERIFY_PEER
#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define ADDRESS "splat.zork.org:6001"

int main(void) {
    EasySSL_CTX::Init_EasySSL();
    EasySSL_CTX ctx(VERSION);
    fprintf(stderr, "ctx_ = %p, bio_ = %p", ctx.ctx_, ctx.bio_);
    ctx.LoadCACertLocations(CAFILE, CADIR);
    ctx.LoadOwnCert(CLIENTCERT);
    ctx.LoadOwnPrivateKey(CLIENTPRK);
    ctx.SetVerifyMode(VERIFY_MODE);
    ctx.SetVerifyDepth(4);
    ctx.SetOptions(SSL_OP_NO_SSLv2);
    ctx.SetCipherSuite(CIPHER_LIST);
    
    EasySSL * easyssl = ctx.SocketConnect(const_cast<char *>(ADDRESS));
    easyssl->SSLConnect();
    
    fprintf(stderr, "Connection Opened\n");
    int err, nwritten;
    char buf[80];

    while (1) {
        if (!fgets(buf, sizeof(buf), stdin))
            break;
        for (nwritten = 0; nwritten < sizeof(buf); nwritten += err) {
            err = easyssl->Write(buf + nwritten, sizeof(buf) - nwritten);
        }
    }
    if (!(err <= 0))
        easyssl->Shutdown();
    else
        easyssl->Clear();
    // delete ssl;
    cout << "Connection Closed" << endl;
    return 0;
}