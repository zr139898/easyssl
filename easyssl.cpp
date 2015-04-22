#include "easyssl.h"

//////////////////////////////////////////////////////////////////////
// Multithread Support begin
//////////////////////////////////////////////////////////////////////
// This array will store all of the mutexes available to OpenSSL.
static MUTEX_TYPE *mutex_buf = NULL;

static void locking_function(int mode, int n, const char * file, int line) {
    if (mode & CRYPTO_LOCK) {
        MUTEX_LOCK(mutex_buf[n]);
    } else {
        MUTEX_UNLOCK(mutex_buf[n]);
    }
}

static unsigned long id_function(void) {
    return ((unsigned long)THREAD_ID);
}

// allocate the memory required to hold the mutexes.
int THREAD_setup(void) {
    int i;

    //CRYPTO_num_locks() returns the required number of locks
    mutex_buf = (MUTEX_TYPE *)malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
    if (!mutex_buf) return 0;

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        MUTEX_SETUP(mutex_buf[i]);
    }
    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
    return 1;
}

int THREAD_cleanup(void) {
    int i;

    if (!mutex_buf) return 0;

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        MUTEX_CLEANUP(mutex_buf[i]);
    }
    free(mutex_buf);
    mutex_buf = NULL;
    return 1;
}

//////////////////////////////////////////////////////////////////////
// Multithread Support end
//////////////////////////////////////////////////////////////////////

void init_OpenSSL(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    if (!THREAD_setup())
        handle_error("OpenSSL thread setup failed!\n");
}

void free_OpenSSL(void) {
    EVP_cleanup();
    ERR_free_strings();
    THREAD_cleanup();
}

void seed_prng(void) {
    RAND_load_file("/dev/urandom", 1024);
}

// This callback employs several functions from the X509 family of functions
// to report the detailed error info.
int verify_callback(int preverify_ok, X509_STORE_CTX * ctx) {
    char data[256];

    if (!preverify_ok) {
        X509 * cert = X509_STORE_CTX_get_current_cert(ctx);
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        int err = X509_STORE_CTX_get_error(ctx);

        fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, "  issuer   = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, "  subject  = %s\n", data);
        fprintf(stderr, "  err %i:%s\n", err, X509_verify_cert_error_string(err));
    }
    return preverify_ok;
}

int wildcmp(const char *wild, const char *string) {
    // Written by Jack Handy - <A href="mailto:jakkhandy@hotmail.com">jakkhandy@hotmail.com</A>
    const char *cp = 0, *mp = 0;
    
    while ((*string) && (*wild != '*')) {
        if ((*wild != *string) && (*wild != '?')) {
            return 0;
        }
        wild++;
        string++;
    }
    
    while (*string) {
        if (*wild == '*') {
            if (!*++wild) {
                return 1;
            }
            mp = wild;
            cp = string+1;
        } else if ((*wild == *string) || (*wild == '?')) {
            wild++;
            string++;
        } else {
            wild = mp;
            string = cp++;
        }
    }

    while (*wild == '*') {
        wild++;
    }
    return !*wild;
}


int FQDNMatch(std::vector<string> acc_san, const char * fqdn) {
    for (std::vector<string>::iterator it = acc_san.begin(); it != acc_san.end(); ++it) {
        cout << "*it = " << *it << endl << "fqdn = " << fqdn << endl;
        if (wildcmp((*it).c_str(), fqdn))
            return 1;
    }
    return 0;
}


DH * dh512 = NULL;
DH * dh1024 = NULL;

// reads the DH params from the files and loads them into the global params.
void init_dhparams(void) {
    BIO * bio;

    bio = BIO_new_file("dh512.pem", "r");
    if (!bio)
        handle_error("Error opening file dh512.pem");
    dh512 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dh512)
        handle_error("Error reading DH parameters from dh512.pem");
    BIO_free(bio);

    bio = BIO_new_file("dh1024.pem", "r");
    if (!bio)
        handle_error("Error opening file dh1024.pem");
    dh1024 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dh1024)
        handle_error("Error reading DH parameters from dh1024.pem");
    BIO_free(bio);
}

// simply switches on the required key size and returns either a 512-bit DH
// params or a 1024-bit DH params.
// This function intertionally does not try to perform any on-the-fly
// generation of params.
DH * tmp_dh_callback(SSL * ssl, int is_export, int keylength) {
    DH * ret;

    if (!dh512 || !dh1024)
        init_dhparams();

    switch (keylength) {
    case 512:
        ret = dh512;
        break;
    case 1024:
    default:
        //generating DH params is too costly to do on the fly
        ret = dh1024;
        break;
    }
    return ret;
}

//////////////////////////////////////////////////////////
EasySSL_CTX::EasySSL_CTX() {
    ctx_ = NULL;
    bio_ = NULL;
}

void EasySSL_CTX::SetVersion(const char * version) {
    printf("Version: %s\n", version);
    if (!strcmp(version, "SSLv3_client")) {
        ctx_ = SSL_CTX_new(SSLv3_client_method());
    } else if (!strcmp(version, "TLSv1_client")) {
        ctx_ = SSL_CTX_new(TLSv1_client_method());
    } else if (!strcmp(version, "TLSv1.1_client")) {
        ctx_ = SSL_CTX_new(TLSv1_1_client_method());
    } else if (!strcmp(version, "Compatible_client")) {
        ctx_ = SSL_CTX_new(SSLv23_client_method());
        SSL_CTX_set_options(ctx_, SSL_OP_NO_SSLv2);
    } else if (!strcmp(version, "SSLv3_server")) {
        ctx_ = SSL_CTX_new(SSLv3_server_method());
        SSL_CTX_set_options(ctx_, SSL_OP_SINGLE_DH_USE);
        SSL_CTX_set_tmp_dh_callback(ctx_, tmp_dh_callback);
    } else if (!strcmp(version, "TLSv1_server")) {
        ctx_ = SSL_CTX_new(TLSv1_server_method());
        SSL_CTX_set_options(ctx_, SSL_OP_SINGLE_DH_USE);
        SSL_CTX_set_tmp_dh_callback(ctx_, tmp_dh_callback);
    } else if (!strcmp(version, "TLSv1.1_server")) {
        ctx_ = SSL_CTX_new(TLSv1_1_server_method());
        SSL_CTX_set_options(ctx_, SSL_OP_SINGLE_DH_USE);
        SSL_CTX_set_tmp_dh_callback(ctx_, tmp_dh_callback);
    } else if (!strcmp(version, "Compatible_server")) {
        ctx_ = SSL_CTX_new(SSLv23_server_method());
        SSL_CTX_set_options(ctx_, SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
        SSL_CTX_set_tmp_dh_callback(ctx_, tmp_dh_callback);
    } else {
        fprintf(stderr, "** illegal SSL/TLS version!\n");
        exit(EXIT_FAILURE);
    }
}

EasySSL_CTX::~EasySSL_CTX(void) {
    fprintf(stderr, "ctx_ = %p, bio_ = %p\n", ctx_, bio_);
    if (ctx_)
        SSL_CTX_free(ctx_);
    if (bio_)
        BIO_free(bio_);
}

void EasySSL_CTX::InitEasySSL(void) {
    init_OpenSSL();
    seed_prng();
}

void EasySSL_CTX::FreeEasySSL(void) {
    free_OpenSSL();
}

char * GetConfString(const CONF * conf, const char * section, const char * key) {
    char * ret;
    if (!(ret = NCONF_get_string(conf, section, key))) {
        fprintf(stderr, "Error finding \"%s\" in [%s]\n", key, section);
        handle_error("Errors finding string");
    }
    return ret;
}

int EasySSL_CTX::LoadConf(const char * conf_filename) {
    long err = 0;
    CONF * conf = NCONF_new(NCONF_default());
    if (!NCONF_load(conf, conf_filename, &err)) {
        if (err == 0) {
            handle_error("Error opening configuration file");
        } else {
            fprintf(stderr, "Error in %s on line %li\n", conf_filename, err);
            handle_error("Errors parsing configuration file");
        }
    }

    SetVersion(GetConfString(conf, "SSLConf", "Version"));
    SetAuthentication(GetConfString(conf, "SSLConf", "Authentication"));
    SetCipherSuite(GetConfString(conf, "SSLConf", "CipherSuite"));

    char * cafile = GetConfString(conf, "Verification", "CAFile");
    char * cadir = GetConfString(conf, "Verification", "CADir");
    if (!strcmp(cafile, ""))
        cafile = NULL;
    if (!strcmp(cadir, ""))
        cadir = NULL;
    cA_file_ = cafile;
    cA_dir_ = cadir;
    LoadCACertLocations(cafile, cadir);
    LoadOwnCert(GetConfString(conf, "Verification", "OwnCert"));
    LoadOwnPrivateKey(GetConfString(conf, "Verification", "OwnPrivateKey"));
    SetCRLFile(GetConfString(conf, "Verification", "CRLFile"));

    char * acc_san_str = GetConfString(conf, "Verification", "AcceptableSubjectAltName");
    
    char * pch = strtok (acc_san_str, "|");
    while (pch) {
        printf("%s\n", pch);
        acc_san_.push_back(string(pch));
        pch = strtok(NULL, "|");
    }
    
    
    return 0;
}

// On success, the function returns 1, otherwise fail.
int EasySSL_CTX::LoadOwnCert(const char * cert_filename) {
    int ret_val;

    ret_val = SSL_CTX_use_certificate_chain_file(ctx_, cert_filename);
    if (ret_val != 1)
        handle_error("Error loading certificate from file");
    return ret_val;
}

// On success, the function returns 1, otherwise fail.
int EasySSL_CTX::LoadOwnPrivateKey(const char * private_key_filename) {
    int ret_val;

    ret_val = SSL_CTX_use_PrivateKey_file(ctx_, private_key_filename, SSL_FILETYPE_PEM);
    if (ret_val != 1)
        handle_error("Error setting cipher list (no valid ciphers)");
    return ret_val;
}

// On success, the function returns 1, otherwise fail.
int EasySSL_CTX::LoadCACertLocations(const char * cA_file, const char * cA_dir) {
    int ret_val;
    cA_file_ = cA_file;
    cA_dir_ = cA_dir;
    
    ret_val = SSL_CTX_load_verify_locations(ctx_, cA_file, cA_dir);
    if (ret_val != 1)
        handle_error("Error loading CA file and/or directory");
    return ret_val;
}

void EasySSL_CTX::SetAuthentication(const char * auth) {
    int mode;
    if (!strcmp(auth, "AUTH_NONE"))
        mode = SSL_VERIFY_NONE;
    if (!strcmp(auth, "AUTH_REQUEST"))
        mode = SSL_VERIFY_PEER;
    if (!strcmp(auth, "AUTH_REQUIRE"))
        mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    SSL_CTX_set_verify(ctx_, mode, verify_callback);
}

// returns 1 if any cipher could be selected and 0 on complete failure
int EasySSL_CTX::SetCipherSuite(const char * cipher_list) {
    int ret_val;
    ret_val = SSL_CTX_set_cipher_list(ctx_, cipher_list);
    if (ret_val != 1)
        handle_error("Error setting cipher list (no valid ciphers)");
    return ret_val;
}

void EasySSL_CTX::SetSAN(vector<string> acc_san) {
    acc_san_ = acc_san;
}

void EasySSL_CTX::SetCRLFile(const char * cRL_file) {
    cRL_file_ = cRL_file;
}

// returns 1 on success, otherwise 0.
int EasySSL_CTX::CreateListenSocket(const char * host_port) {
    char * port = new char[strlen(host_port) + 1];
    strcpy(port, host_port);
    bio_ = BIO_new_accept(port);
    delete [] port;
    if (!bio_) {
        handle_error("Error creating server socket");
        return 0;
    }
    if (BIO_do_accept(bio_) <= 0) {
        handle_error("Error binding server socket");
        return 0;
    }
    return 1;
}

// awaits an incoming connection, and returns the established EasySSL object.
EasySSL * EasySSL_CTX::AcceptSocketConnection() {
    if (BIO_do_accept(bio_) <= 0)
        handle_error("Error accepting connection");
    BIO * client = BIO_pop(bio_);
    SSL * ssl;
    if (!(ssl = SSL_new(ctx_)))
        handle_error("Error creating new SSL");
    SSL_set_accept_state(ssl);
    SSL_set_bio(ssl, client, client);
    EasySSL * easyssl = new EasySSL(ssl);
    easyssl->SetSAN(acc_san_);
    easyssl->SetCA(cA_file_, cA_dir_);
    easyssl->SetCRLFile(cRL_file_);
    return easyssl;
}

EasySSL * EasySSL_CTX::SocketConnect(const char * address) {
    char * addr = new char[strlen(address) + 1];
    strcpy(addr, address);
    
    BIO * bio = BIO_new_connect(addr);
    delete [] addr;
    if (!bio)
        handle_error("Error creating connection BIO");
    if (BIO_do_connect(bio) <= 0)
        handle_error("Error connecting to remote machine");
    SSL * ssl = SSL_new(ctx_);
    if (!ssl)
        handle_error("Error creating new SSL");
    // specify a BIO for SSL object to use.
    SSL_set_bio(ssl, bio, bio);
    EasySSL * easyssl = new EasySSL(ssl);
    easyssl->SetSAN(acc_san_);
    easyssl->SetCA(cA_file_, cA_dir_);
    easyssl->SetCRLFile(cRL_file_);
    return easyssl;
}

////////////////////////////////////////////////////////////
EasySSL::EasySSL(SSL * ssl) {
    ssl_ = ssl;
}

EasySSL::EasySSL(const EasySSL & easyssl) {
    ssl_ = easyssl.ssl_;
}

EasySSL::~EasySSL() {
    if (ssl_)
        SSL_free(ssl_);
}

void EasySSL::SetSAN(vector<string> acc_san) {
    acc_san_ = acc_san;
}

void EasySSL::SetCRLFile(const char * cRL_file) {
    cRL_file_ = cRL_file;
}

void EasySSL::SetCA(const char * cA_file, const char * cA_dir) {
    cA_file_ = cA_file;
    cA_dir = cA_dir;
}

// on success, return 1, otherwise 0;
int EasySSL::AcceptSSLConnection() {
    if (SSL_accept(ssl_) <= 0) {
        handle_error("Error accepting SSL connection");
        return 0;
    }
    if (!CRLCheck()) {
        handle_error("Error checking peer certificate against CRL");
        return 0;
    }
    long post_err;
    if ((post_err = PostConnectionCheck()) != X509_V_OK) {
        fprintf(stderr, "-Error: peer certificate: %s\n",
            X509_verify_cert_error_string(post_err));
        handle_error("Error checking SSL object after connection");
        return 0;
    }
    return 1;
}

int EasySSL::SSLConnect() {
    int val = SSL_connect(ssl_);
    if(val <= 0) {
        fprintf(stderr, "val = %d\n", val);
        handle_error("Error connecting SSL connection");
        fprintf(stderr, "SSL_get_error(ssl_, val) = %d", SSL_get_error(ssl_, val));
        return 0;
    }
    if (!CRLCheck())
        handle_error("Error checking peer certificate against CRL");
    long post_err;
    if ((post_err = PostConnectionCheck()) != X509_V_OK) {
        fprintf(stderr, "-Error: peer certificate: %s\n",
            X509_verify_cert_error_string(post_err));
        handle_error("Error checking SSL object after connection");
        return 0;
    }
    
    return 1;
}

char * GetDistributionPoint(X509 * cert) {
    STACK_OF(DIST_POINT) * dps = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (sk_DIST_POINT_num(dps) > 0) {
        DIST_POINT * dp = sk_DIST_POINT_pop(dps);
        STACK_OF(GENERAL_NAME) * names = dp->distpoint->name.fullname;
        if (sk_GENERAL_NAME_num(names) > 0) {
            GENERAL_NAME * name = sk_GENERAL_NAME_pop(names);
            if (name->type == GEN_URI) {
                ASN1_IA5STRING * uri = name->d.uniformResourceIdentifier;
                return (char *)uri->data;
            }
        }
    }
    return 0;
}

char * GetCertCRLURI(X509 * cert) {
    char * uri;

    if (cert && (uri = GetDistributionPoint(cert)) != 0)
        return uri;
    //if (issuer && (uri = GetDistributionPoint(issuer)) != 0)
    //  return uri;
    return 0;
}

int RetrieveCRLviaHTTP(const char * uri) {
BIO * cbio, * out;
    int len;
    char tmpbuf[1024];
    ERR_load_crypto_strings();

    char host[100];
    int port = 80;
    char path[100];
    char httpget[100];
    int succ_parsing = 0;

    if (sscanf(uri, "http://%99[^:]:%i/%199[^\n]", host, &port, path) == 3) {
        succ_parsing = 1;
    } else if (sscanf(uri, "http://%99[^/]/%199[^\n]", host, path) == 2) {
        succ_parsing = 1;
    } else if (sscanf(uri, "http://%99[^:]:%i[^\n]", host, &port) == 2) { succ_parsing = 1;
    } else if (sscanf(uri, "http://%99[^\n]", host) == 1) {
        succ_parsing = 1;
    }

    if (!succ_parsing) {
        handle_error("Error parsing the URI of crlDistributionPoints");
    }
    char portstr[100];
    sprintf(portstr, "%d", port);
    cbio = BIO_new(BIO_s_connect());
    BIO_set_conn_hostname(cbio, host);
    BIO_set_conn_port(cbio, portstr);
    
    out = BIO_new_file("crl.pem", "w");

    if (BIO_do_connect(cbio) <= 0) {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
    }
    BIO_printf(cbio, "GET /%s HTTP/1.1\r\nConnection: close\r\n\r\n", path);
    while (1) {
        len = BIO_read(cbio, tmpbuf, 1024);
        if (len <= 0) break;

        BIO_write(out, tmpbuf, len);
    }
    BIO_free(cbio);
    BIO_free(out);
}

int EasySSL::CRLCheck() {
    X509 * cert;
    X509_STORE * store;
    X509_LOOKUP * lookup;
    X509_STORE_CTX * verify_ctx;
    
    if (! (cert = SSL_get_peer_certificate(ssl_)))
        return 1;

    // create the cert store and set the verify callback
    if (!(store = X509_STORE_new()))
        handle_error("Error creating X509_STORE_CTX object");
    X509_STORE_set_verify_cb_func(store, verify_callback);

    // load the CA certificates and CRLs
    // load_locations can be replaced with lookups instead.
    if (X509_STORE_load_locations(store, cA_file_, cA_dir_) != 1)
        handle_error("Error loading the CA file or directory");
    // create a X509_LOOKUP object, add to the store,  assign the lookup the CRL file
    if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())))
        handle_error("Error creating X509_LOOKUP object");

    printf("cRL_file_ = %s\n", cRL_file_);
    
    if (X509_load_crl_file(lookup, cRL_file_, X509_FILETYPE_PEM) != 1) {
        fprintf(stderr, "No local CRL file. Trying to download CRL\n");

        char * uri = GetCertCRLURI(cert);
        printf("uri = %s\n", uri);
        if (!uri)
            handle_error("Error fetching crlDistributionPoint from certificate");
        if (!RetrieveCRLviaHTTP(uri)) {
            fprintf(stderr, "Fail to download CRL via HTTP\n");
            handle_error("Error downloading CRL");
        } else {
            fprintf(stderr, "CRL file downloaded\n");
        }
        
        if (X509_load_crl_file(lookup, cRL_file_, X509_FILETYPE_PEM) != 1)
            handle_error("Error reading the CRL file");
    }
    
    // enabling verification against CRLs is not possible in prior version
    // set the flags of the store so that CRLs are consulted
    // By setting flags in the store, they are automatically copied to the store ctx
    // X509_V_FLAG_CRL_CHECK instructs the contexts to check client certs for possible revocation.
    // This flag only checks the identity cert not the chain.
    // X509_V_FLAG_CRL_CHECK_ALL checks the entire chain.
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

    // create a verification context and initialize it
    if (!(verify_ctx = X509_STORE_CTX_new()))
        handle_error("Error creating X509_STORE_CTX object");
    // X509_STORE_CTX_init did not return an error condition in prior version
    // This last arg allows us to pass in the complete peer cert chain for verification.
    // This is often necessary, since the verifying party may not have a complete list of certs
    if (X509_STORE_CTX_init(verify_ctx, store, cert, NULL) != 1)
        handle_error("Error initializing verification context");

    // verify the certificate, 1 on success, 0 on failure.
    return X509_verify_cert(verify_ctx);
}

// post_connection_check is implemented as a wrapper around
// SSL_get_verify_result, which performs our extra peer cert checks.
// It uses the reserved error code X509_V_ERR_APPLICATION_VERIFICATION to
// indicate errors where there is no peer cert present or the cert presented
// does not match the expected FQDN.
// This function will return an error in the following circumstances:
// * If no peer cert is found
// * If it is called with a NULL second argument, i.e., if no FQDN is specified
//   to compare against.
// * If the dNSName fields found (if any) do not match the host arg and the
//   commonName also doesn't match the host arg (if found)
// * Any time the SSL_get_verify_result routine returns an error
// Otherwise, X509_V_OK will be returned.
long EasySSL::PostConnectionCheck() {
    X509 * cert;
    X509_NAME * subj;
    char data[256];
    int extcount;
    int ok = 0;

    cout << "in post connection check" << endl;
    for (vector<string>::iterator it = acc_san_.begin(); it != acc_san_.end(); it++) {
        cout << *it << endl;
    }

    
    // no cert, no check
    if (! (cert = SSL_get_peer_certificate(ssl_)))
        return SSL_get_verify_result(ssl_);

    if (!acc_san_.size())
        goto err_occurred;
    if ((extcount  = X509_get_ext_count(cert)) > 0) {
        int i;
        // iterate through the extensions and use the extension-specific
        // parsing routes to find all extensions that are subjectAltName field
        for (i = 0; i < extcount; i++) {
            char * extstr;  // hold the extracted short name of extension
            X509_EXTENSION * ext;
            ext = X509_get_ext(cert, i);
            extstr = (char *)OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
            if (!strcmp(extstr, "subjectAltName")) {
                int j;
                const unsigned char * data;
                STACK_OF(CONF_VALUE) * val;
                CONF_VALUE * nval;
                const X509V3_EXT_METHOD * meth;
                void * ext_str = NULL;
                // extract the X509V3_EXT_METHOD object from the extension.
                // This object is a container of extension-specific function
                // for manipulating the data within the extension.
                if (!(meth = X509V3_EXT_get(ext)))
                    break;
                data = ext->value->data;
                // d2i and i2v functions convert the raw data in subjectAleName
                // to a stack of CONF_VALUE objects. This is neccessary to make
                // it simple to iterate over the several kinds of fields in the
                // subjectAltName so that we may find the dNSName field(s).
                if (meth->it)
                    ext_str = ASN1_item_d2i(NULL, &data, ext->value->length,
                                            ASN1_ITEM_ptr(meth->it));
                else
                    ext_str = meth->d2i(NULL, &data, ext->value->length);
                val = meth->i2v(meth, ext_str, NULL);
                // Since a subjectAltName field may itself contain several
                // fields, we must then iterate to find any dNSName fields.
                // We check each member of this CONF_VALUE stack to see if we
                // have a match for the host string in a dNSName field.
                for (j = 0; j < sk_CONF_VALUE_num(val); j++) {
                    nval = sk_CONF_VALUE_value(val, j);
                    //if (!strcmp(nval->name, "DNS") && FQDNMatch(acc_san_, nval->value))
                    if (FQDNMatch(acc_san_, nval->value))
                    {
                        ok = 1;
                        break;
                    }
                }
            }
            // As soon as we find a match (host), we stop the iterations over
            // all the extensions.
            if (ok)
                break;
        }
    }
    if (!ok)
        goto err_occurred;
    X509_free(cert);
    return SSL_get_verify_result(ssl_);

err_occurred:
    if (cert)
        X509_free(cert);
    return X509_V_ERR_APPLICATION_VERIFICATION;
}

int EasySSL::GetShutdown() {
    return SSL_get_shutdown(ssl_);
}

int EasySSL::Shutdown() {
    SSL_shutdown(ssl_);
    // or SSL_clear(ssl); check the doc
}

int EasySSL::Clear() {
    SSL_clear(ssl_);
}
    // the return type must be redefined.
int EasySSL::Read(void * buf, int num) {
    return SSL_read(ssl_, buf, num);
}
int EasySSL::Write(const void * buf, int num) {
    return SSL_write(ssl_, buf, num);
}
