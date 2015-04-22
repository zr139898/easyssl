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
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/conf.h>


#include <openssl/x509_vfy.h>

//////////////////////////////////////////////////////////////////////
// Multithread Support begin
//////////////////////////////////////////////////////////////////////
// platform-dependent macros
#ifndef WIN32
#include <unistd.h>
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

#if defined(WIN32)
#define MUTEX_TYPE HANDLE
#define MUTEX_SETUP(x) (x) = CreateMutex(NULL, FALSE, NULL)
#define MUTEX_CLEANUP(x) CloseHandle(x)
#define MUTEX_LOCK(x) WaitForSingleObject((x), INFINITE)
#define MUTEX_UNLOCK(x) RelieaseMutex(x)
#define THREAD_ID GetCurrentThreadId()
#elif defined(_POSIX_THREADS)
// _POSIX_THREADS is normally defined in unistd.h if pthreads are available on your platform.
#define MUTEX_TYPE       pthread_mutex_t
#define MUTEX_SETUP(x)   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)    pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)  pthread_mutex_unlock(&(x))
#define THREAD_ID        pthread_self()
#else
#error You must define mutex operations appropriate for your platform!
#endif

// allocate the memory required to hold the mutexes.
// we must call call THREAD_setup before our programs starts threads
// or call OpenSSL functions.
int THREAD_setup(void);
// reclaim any memory used for the mutexes.
int THREAD_cleanup(void);
//////////////////////////////////////////////////////////////////////
// Multithread Support end
//////////////////////////////////////////////////////////////////////

#define handle_error(msg) {fprintf(stderr, "** %s:%i %s\n", __FILE__, __LINE__, msg); \
    ERR_print_errors_fp(stderr); \
    exit(-1);}

using namespace std;

class EasySSL_CTX;
class EasySSL;

void init_OpenSSL(void);
void free_OpenSSL(void);
void seed_prng(void);

int verify_callback(int preverify_ok, X509_STORE_CTX * ctx);

class EasySSL_CTX {
public:
    SSL_CTX * ctx_;
    BIO * bio_;
    vector<string> acc_san_;
    const char * cA_file_;
    const char * cA_dir_;
    const char * cRL_file_;
    EasySSL_CTX();
    ~EasySSL_CTX();
    
    // Call InitEasySSL initially and FreeEasySSL before exiting
    static void InitEasySSL();  // called only once
    static void FreeEasySSL();  // called only once
    
    // provide two options: conf file or using the function for settings.
    int LoadConf(const char * conf_filename);

    void SetVersion(const char * version);
    void SetVerifyMode(const char * verify_mode);
    void SetVerifyDepth(int depth);
    int SetCipherSuite(const char * cipher_list);
    void SetSAN(vector<string> acc_san);
    void SetCRLFile(const char * cRL_file);
    
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
    vector<string> acc_san_;
    const char * cA_file_;
    const char * cA_dir_;
    const char * cRL_file_;
    
    EasySSL(SSL * ssl);
    EasySSL(const EasySSL & easyssl);
    ~EasySSL();
    void SetSAN(vector<string> acc_san);
    void SetCA(const char * cA_file, const char * cA_dir);
    void SetCRLFile(const char * cRL_file);
    
    int AcceptSSLConnection();
    int SSLConnect();
    int CRLCheck();
    long PostConnectionCheck();
    int Shutdown();
    int GetShutdown();
    int Clear();
    int Read(void * buf, int num);
    int Write(const void * buf, int num);
};

#endif