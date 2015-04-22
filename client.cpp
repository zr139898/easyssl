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

    ctx.LoadConf("client.cnf");

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
    int len, len_written;
    char buf[80];

    while (1) {
        if (!fgets(buf, sizeof(buf), stdin))
            break;
        for (len_written = 0; len_written < sizeof(buf); len_written += len) {
            len = easyssl->Write(buf + len_written, sizeof(buf) - len_written);
        }
    }
    easyssl->Shutdown();
    delete easyssl;
    
    cout << "Connection Closed" << endl;

    EasySSL_CTX::FreeEasySSL();
    return 0;
}