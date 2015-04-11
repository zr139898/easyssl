#ifndef SSL_MULTITHREAD_H_
#define SSL_MULTITHREAD_H_

#ifndef WIN32
#include <unistd.h>
#include <pthread.h>
#else
#include <windows.h>
#endif

#include <openssl/ssl.h>

// allocate the memory required to hold the mutexes.
// we must call call THREAD_setup before our programs starts threads
// or call OpenSSL functions.
int THREAD_setup(void);
// reclaim any memory used for the mutexes.
int THREAD_cleanup(void);

#endif