#include "easyssl.h"

void handle_error(const char * file, int lineno, const char * msg) {
    fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void init_OpenSSL(void) {
    if (!THREAD_setup() || !SSL_library_init()) {
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        exit(-1);
    }
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
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
        int_error("Error opening file dh512.pem");
    dh512 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dh512)
        int_error("Error reading DH parameters from dh512.pem");
    BIO_free(bio);

    bio = BIO_new_file("dh1024.pem", "r");
    if (!bio)
        int_error("Error opening file dh1024.pem");
    dh1024 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dh1024)
        int_error("Error reading DH parameters from dh1024.pem");
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

EasySSL_CTX::~EasySSL_CTX() {
    fprintf(stderr, "ctx_ = %p, bio_ = %p\n", ctx_, bio_);
    if (ctx_)
        SSL_CTX_free(ctx_);
    if (bio_)
        BIO_free(bio_);
}

void EasySSL_CTX::InitEasySSL() {
    init_OpenSSL();
    seed_prng();
}

char * GetConfString(const CONF * conf, const char * section, const char * key) {
    char * ret;
    if (!(ret = NCONF_get_string(conf, section, key))) {
        fprintf(stderr, "Error finding \"%s\" in [%s]\n", key, section);
        int_error("Errors finding string");
    }
    return ret;
}

int EasySSL_CTX::LoadConf(const char * conf_filename) {
    long err = 0;
    CONF * conf = NCONF_new(NCONF_default());
    if (!NCONF_load(conf, conf_filename, &err)) {
        if (err == 0)
            int_error("Error opening configuration file");
        else {
            fprintf(stderr, "Error in %s on line %li\n", conf_filename, err);
            int_error("Errors parsing configuration file");
        }
    }

    SetVersion(GetConfString(conf, "SSLConf", "Version"));
    SetVerifyMode(GetConfString(conf, "SSLConf", "VerifyMode"));
    SetVerifyDepth(atoi(GetConfString(conf, "SSLConf", "VerifyDepth")));
    SetCipherSuite(GetConfString(conf, "SSLConf", "CipherSuite"));

    char * cafile = GetConfString(conf, "Verification", "CAFile");
    char * cadir = GetConfString(conf, "Verification", "CADir");
    if (!strcmp(cafile, ""))
        cafile = NULL;
    if (!strcmp(cadir, ""))
        cadir = NULL;
    LoadCACertLocations(cafile, cadir);
    LoadOwnCert(GetConfString(conf, "Verification", "OwnCert"));
    LoadOwnPrivateKey(GetConfString(conf, "Verification", "OwnPrivateKey"));

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
        int_error("Error loading certificate from file");
    return ret_val;
}

// On success, the function returns 1, otherwise fail.
int EasySSL_CTX::LoadOwnPrivateKey(const char * private_key_filename) {
    int ret_val;

    ret_val = SSL_CTX_use_PrivateKey_file(ctx_, private_key_filename, SSL_FILETYPE_PEM);
    if (ret_val != 1)
        int_error("Error setting cipher list (no valid ciphers)");
    return ret_val;
}

// On success, the function returns 1, otherwise fail.
int EasySSL_CTX::LoadCACertLocations(const char * cA_file, const char * cA_dir) {
    int ret_val;

    ret_val = SSL_CTX_load_verify_locations(ctx_, cA_file, cA_dir);
    if (ret_val != 1)
        int_error("Error loading CA file and/or directory");
    return ret_val;
}

void EasySSL_CTX::SetVerifyMode(const char * verify_mode) {
    int mode;
    if (!strcmp(verify_mode, "AUTH_NONE"))
        mode = SSL_VERIFY_NONE;
    if (!strcmp(verify_mode, "AUTH_REQUEST"))
        mode = SSL_VERIFY_PEER;
    if (!strcmp(verify_mode, "AUTH_REQUIRE"))
        mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    SSL_CTX_set_verify(ctx_, mode, verify_callback);
}

void EasySSL_CTX::SetVerifyDepth(int depth = 9) {
    return SSL_CTX_set_verify_depth(ctx_, depth);
}

// returns 1 if any cipher could be selected and 0 on complete failure
int EasySSL_CTX::SetCipherSuite(const char * cipher_list) {
    int ret_val;
    ret_val = SSL_CTX_set_cipher_list(ctx_, cipher_list);
    if (ret_val != 1)
        int_error("Error setting cipher list (no valid ciphers)");
    return ret_val;
}

void EasySSL_CTX::SetHostList(vector<string> acc_san) {
    acc_san_ = acc_san;
}

// returns 1 on success, otherwise 0.
int EasySSL_CTX::CreateListenSocket(const char * host_port) {
    char * port = new char[strlen(host_port) + 1];
    strcpy(port, host_port);
    bio_ = BIO_new_accept(port);
    delete [] port;
    if (!bio_) {
        int_error("Error creating server socket");
        return 0;
    }
    if (BIO_do_accept(bio_) <= 0) {
        int_error("Error binding server socket");
        return 0;
    }
    return 1;
}

// awaits an incoming connection, and returns the established EasySSL object.
EasySSL * EasySSL_CTX::AcceptSocketConnection() {
    if (BIO_do_accept(bio_) <= 0)
        int_error("Error accepting connection");
    BIO * client = BIO_pop(bio_);
    SSL * ssl;
    if (!(ssl = SSL_new(ctx_)))
        int_error("Error creating new SSL");
    SSL_set_accept_state(ssl);
    SSL_set_bio(ssl, client, client);
    EasySSL * easyssl = new EasySSL(ssl);
    easyssl->SetHostList(acc_san_);
    return easyssl;
}

EasySSL * EasySSL_CTX::SocketConnect(const char * address) {
    char * addr = new char[strlen(address) + 1];
    strcpy(addr, address);
    
    BIO * bio = BIO_new_connect(addr);
    delete [] addr;
    if (!bio)
        int_error("Error creating connection BIO");
    if (BIO_do_connect(bio) <= 0)
        int_error("Error connecting to remote machine");
    SSL * ssl = SSL_new(ctx_);
    if (!ssl)
        int_error("Error creating new SSL");
    // specify a BIO for SSL object to use.
    SSL_set_bio(ssl, bio, bio);
    EasySSL * easyssl = new EasySSL(ssl);
    easyssl->SetHostList(acc_san_);
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

void EasySSL::SetHostList(vector<string> acc_san) {
    acc_san_ = acc_san;
}

// on success, return 1, otherwise 0;
int EasySSL::AcceptSSLConnection() {
    int val = SSL_accept(ssl_);
    if (val <= 0) {
        fprintf(stderr, "val = %d\n", val);
        int_error("Error accepting SSL connection");
        fprintf(stderr, "SSL_get_error(ssl_, val) = %d", SSL_get_error(ssl_, val));
        return 0;
    }
    long post_err;
    if ((post_err = PostConnectionCheck()) != X509_V_OK) {
        fprintf(stderr, "-Error: peer certificate: %s\n",
            X509_verify_cert_error_string(post_err));
        int_error("Error checking SSL object after connection");
        return 0;
    }
    return 1;
}

int EasySSL::SSLConnect() {
    int val = SSL_connect(ssl_);
    if(val <= 0) {
        fprintf(stderr, "val = %d\n", val);
        int_error("Error connecting SSL connection");
        fprintf(stderr, "SSL_get_error(ssl_, val) = %d", SSL_get_error(ssl_, val));
        return 0;
    }

    long post_err;
    if ((post_err = PostConnectionCheck()) != X509_V_OK) {
        fprintf(stderr, "-Error: peer certificate: %s\n",
            X509_verify_cert_error_string(post_err));
        int_error("Error checking SSL object after connection");
        return 0;
    }
    
    return 1;
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
