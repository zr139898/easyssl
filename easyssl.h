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

void init_OpenSSL(void);
void free_OpenSSL(void);
void seed_prng(void);
int verify_callback(int preverify_ok, X509_STORE_CTX * ctx);

// EasySSL_CTX objects server as containers for settings for the
// TLS/SSL connection to be made by a programs.
// It's also used to establish an TCP/IP socket connection for the TLS/SSL to use as the underlying communication channel
class EasySSL_CTX;
// A wrapper around an TLS/SSL connection.
// used to make an TLS/SSL handshake, do I/O operations through the
// TLS/SSL connection, and shutdown the connection.
class EasySSL;

class EasySSL_CTX {
private:
    SSL_CTX * ctx_;
    BIO * bio_;  // for server, holds the listening socket
    vector<string> acc_san_;  // hold the AcceptableSubjectAltName in confile
    const char * cA_file_;
    const char * cRL_file_;

public:
    // Application will call InitEasySSL initially and FreeEasySSL before exiting
    static void InitEasySSL();  // called only once
    static void FreeEasySSL();  // called only once

    EasySSL_CTX();
    ~EasySSL_CTX();
    
    // provide two options: conf file or using the function for settings.
    void LoadConf(const char * conf_filename);

    void SetVersion(const char * version);
    void SetAuthentication(const char * auth);
    void SetCipherSuite(const char * cipher_list);
    
    void LoadCACert(const char * cA_filename);
    void SetCRLFile(const char * cRL_filename);
    // call the two following functions only if the entity has a certificate
    void LoadOwnCert(const char * cert_filename);
    void LoadOwnPrivateKey(const char * private_key_filename);
    
    void Set_acc_san(vector<string> acc_san);
    
    // for server, create a listening TCP/IP socket and binding the port to it.
    void CreateListenSocket(const char * host_port);
    // for server, blocks and awaits an incoming TCP/IP socket connection, and
    // returns an EasySSL object which uses this socket connection as
    // the underlying communication channel and inherits the setting of
    // this EasySSL_CTX
    EasySSL * AcceptSocketConnection();
    // for client, attempt to establish a TCP/IP socket connection to remote
    // server, and returns an EasySSL object which uses this socket connection
    // as the underlying communication channel and inherits the setting of
    // this EasySSL_CTX
    EasySSL * SocketConnect(const char * address);
};

class EasySSL {
private:
    // Making EasySSL_CTX a friend to EasySSL enables EasySSL_CTX to pass data
    // "acc_san_", "cA_file_" and "cRL_file_" to EasySSL when an EasySSL_CTX
    // object creates a new EasySSL object. I dont't want to make three public
    // set methods to set these data in case that the client can use them.
    friend class EasySSL_CTX;
    
    SSL * ssl_;
    vector<string> acc_san_; // hold the AcceptableSubjectAltName in conf file
    const char * cA_file_;
    const char * cRL_file_;
    
    // Check the status of peer certificates against the certificate revocation
    // list of the CA
    int CRLCheck();
    // Check the subjectAltName extensions in the peer certificate against
    // AcceptableSubjectAltName in the conf file
    long SANCheck();

public:
    EasySSL(SSL * ssl);
    EasySSL(const EasySSL & easyssl);
    ~EasySSL();

    // for server, blocks and waits for a client to initiate a TLS/SSL handshake
    void SSLAccept();
    // for client, initiates a TLS/SSL handshake with a server.
    void SSLConnect();
    void Shutdown();

    // blocking read operation.
    // tried to read num bytes from the TLS/SSL connection into the buffer buf.
    // return value:
    // ** > 0: The read operation was successful; the return value is the number
    //         of bytes actually read from the TLS/SSL connection.
    // ** = 0: The read operation was not successful. The reason is a shutdown
    //         due to a "close notify" alert sent by the peer.
    // ** < 0: The read operation was not successful. Unknown reason.
    int Read(void * buf, int num);
    // blocking write operation.
    // tries to write num bytes from buf into the TLS/SSL connection.
    // return value:
    // ** > 0: The write operation was successful; the return value is the
    //         number of bytes actuaaly written to the TLS/SSL connection.
    // ** = 0: The write operation was not successful. The reason is the
    //         underlying connection was closed.
    // ** < 0: The write operation was not successful. Unknown reason.
    int Write(const void * buf, int num);
};

#endif