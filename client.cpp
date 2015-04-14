#include "easyssl.h"
#include <iostream>
using namespace std;

#define VERSION "Compatible_client"
#define CLIENTCERT "client.pem"
#define CLIENTPRK "clientprk.pem"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define VERIFY_MODE "AUTH_REQUEST"
#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define ADDRESS "splat.zork.org:6001"

int main(void) {
    EasySSL_CTX::InitEasySSL();
    EasySSL_CTX ctx;

    ctx.LoadConf("clientconf.cnf");

    // ctx.SetVersion(VERSION);
    // ctx.SetVerifyMode(VERIFY_MODE);
    // ctx.SetVerifyDepth(4);
    // ctx.SetCipherSuite(CIPHER_LIST);
    // ctx.LoadCACertLocations(CAFILE, CADIR);
    // ctx.LoadOwnCert(CLIENTCERT);
    // ctx.LoadOwnPrivateKey(CLIENTPRK);
    
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