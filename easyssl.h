#ifndef EASYSSL_H_
#define EASYSSL_H_

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include "ssl_multithread.h"
using namespace std;

#ifndef WIN32
#include <pthread.h>
#define THREAD_CC *
#define THREAD_TYPE pthread_t
#define THREAD_CREATE(tid, entry, arg) pthread_create(&(tid), NULL, \
                                                      (entry), (arg))
#else
#include <windows.h>
#define THREAD_CC __cdecl
#define THREAD_TYPE DWORD
#define THREAD_CREATE(tid, entry, arg) do { _beginthread((entry), 0, (arg)); \
        (tid) = GetCurrentThreadId();                                   \
    } while (0)
#endif

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

class EasySSL_CTX;
class EasySSL;

void handle_error(const char * file, int lineno, const char * msg);

void init_OpenSSL(void);

void seed_prng(void);

int verify_callback(int preverify_ok, X509_STORE_CTX * ctx);

class EasySSL_CTX {
public:
    SSL_CTX * ctx_;
    BIO * bio_;
    vector<string> host_list_;
    EasySSL_CTX();
    ~EasySSL_CTX();
    static void InitEasySSL();  // called only once
    
    // provide two options: conf file or using the function for settings.
    int LoadConf(const char * conf_filename);

    void SetVersion(const char * version);
    void SetVerifyMode(const char * verify_mode);
    void SetVerifyDepth(int depth);
    int SetCipherSuite(const char * cipher_list);
    void SetHostList(vector<string> host_list);
    
    int LoadOwnCert(const char * cert_file_name);
    int LoadOwnPrivateKey(const char * private_key_file_name);
    int LoadCACertLocations(const char * cA_file, const char * cA_dir);
        
    int CreateListenSocket(const char * host_port);
    EasySSL * AcceptSocketConnection();
    EasySSL * SocketConnect(const char * address);
};

class EasySSL {
public:
    SSL * ssl_;
    vector<string> host_list_;
    
    EasySSL(SSL * ssl);
    EasySSL(const EasySSL & easyssl);
    ~EasySSL();
    void SetHostList(vector<string> host_list);
    int AcceptSSLConnection();
    int SSLConnect();
    long PostConnectionCheck();
    int Shutdown();
    int GetShutdown();
    int Clear();
    int Read(void * buf, int num);
    int Write(const void * buf, int num);
};

#endif