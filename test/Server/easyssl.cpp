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
int ThreadSetup(void) {
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

int ThreadCleanup(void) {
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

//////////////////////////////////////////////////////////////////////
// Utility Function begin
//////////////////////////////////////////////////////////////////////

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

int SANMatch(std::vector<string> acc_san, const char * fqdn) {
    for (std::vector<string>::iterator it = acc_san.begin(); it != acc_san.end(); ++it) {
        if (wildcmp((*it).c_str(), fqdn))
            return 1;
    }
    return 0;
}

X509_CRL * LoadCRL(const char * infile) {
	X509_CRL * x = NULL;
	BIO *in = NULL;

    if ((in = BIO_new(BIO_s_file())) == NULL) {
        HANDLE_ERROR("Error creating a file BIO");
		goto end;
    }

    if (BIO_read_filename(in,infile) <= 0) {
        HANDLE_ERROR("Error reading the CRL file");
        goto end;
    }
    if ((x = PEM_read_bio_X509_CRL(in,NULL,NULL,NULL)) == NULL) {
        HANDLE_ERROR("Error parsing CRL file with PEM format");
		goto end;
    }
    
end:
	BIO_free(in);
	return(x);
}

char * GetCrlDistributionPointURI(const char * cert_filename) {
    FILE * fp;
    X509 * cert;
    if (!(fp = fopen(cert_filename, "r")))
        HANDLE_ERROR("Error reading CA certificate file");
    if (!(cert = PEM_read_X509(fp, 0, 0, 0)))
        HANDLE_ERROR("Error reading CA certificate in file");
    fclose(fp);
    
    if (cert) {
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
    }
    return 0;
}

int RetrieveFileviaHTTP(const char * uri, const char * cRL_filename) {
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
        HANDLE_ERROR("Error parsing the URI of crlDistributionPoints");
    }
    char portstr[100];
    sprintf(portstr, "%d", port);
    cbio = BIO_new(BIO_s_connect());
    BIO_set_conn_hostname(cbio, host);
    BIO_set_conn_port(cbio, portstr);
    
    out = BIO_new_file(cRL_filename, "w");

    if (BIO_do_connect(cbio) <= 0) {
        fprintf(stderr, "Error connecting to %s:%s\n", host, portstr);
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

char * GetConfString(const CONF * conf, const char * section, const char * key) {
    char * ret;
    if (!(ret = NCONF_get_string(conf, section, key))) {
        fprintf(stderr, "Error finding \"%s\" in [%s]\n", key, section);
        HANDLE_ERROR("Errors finding string");
    }
    return ret;
}

DH * dh512 = NULL;
DH * dh1024 = NULL;

// reads the DH params from the files and loads them into the global params.
void init_dhparams(void) {
    BIO * bio;

    bio = BIO_new_file("dh512.pem", "r");
    if (!bio)
        HANDLE_ERROR("Error opening file dh512.pem");
    dh512 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dh512)
        HANDLE_ERROR("Error reading DH parameters from dh512.pem");
    BIO_free(bio);

    bio = BIO_new_file("dh1024.pem", "r");
    if (!bio)
        HANDLE_ERROR("Error opening file dh1024.pem");
    dh1024 = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dh1024)
        HANDLE_ERROR("Error reading DH parameters from dh1024.pem");
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

//////////////////////////////////////////////////////////////////////
// Utility Function end
//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
// EasySSL_CTX begin
//////////////////////////////////////////////////////////////////////
void EasySSL_CTX::InitEasySSL(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    RAND_load_file("/dev/urandom", 1024);  // seed prng
    if (!ThreadSetup())
        HANDLE_ERROR("OpenSSL thread setup failed!\n");
}

void EasySSL_CTX::FreeEasySSL(void) {
    EVP_cleanup();
    ERR_free_strings();
    ThreadCleanup();
}

EasySSL_CTX::EasySSL_CTX() {
    ctx_ = NULL;
    bio_ = NULL;

    // create the cert store
    if (!(x509_store_ = X509_STORE_new()))
        HANDLE_ERROR("Error creating X509_STORE object");
}

EasySSL_CTX::EasySSL_CTX(const EasySSL_CTX & ctx) {
    SetVersion(ctx.version_);
    SetVerify(ctx.verify_);
    SetCipherSuite(ctx.cipher_suite_);
    LoadCACert(ctx.cA_file_);
    LoadCRLFile(ctx.cRL_file_);
    LoadOwnCert(ctx.own_cert_file_);
    LoadOwnPrivateKey(ctx.own_prk_file_);
    acc_san_ = ctx.acc_san_;
    if (!(x509_store_ = X509_STORE_new()))
        HANDLE_ERROR("Error creating X509_STORE object");
}
EasySSL_CTX::~EasySSL_CTX(void) {
    if (ctx_)
        SSL_CTX_free(ctx_);
    if (bio_)
        BIO_free(bio_);
}

void EasySSL_CTX::LoadConf(const char * conf_filename) {
    long err = 0;
    CONF * conf = NCONF_new(NCONF_default());
    if (!NCONF_load(conf, conf_filename, &err)) {
        if (err == 0) {
            HANDLE_ERROR("Error opening configuration file");
        } else {
            fprintf(stderr, "Error in %s on line %li\n", conf_filename, err);
            HANDLE_ERROR("Errors parsing configuration file");
        }
    }

    SetVersion(GetConfString(conf, NULL, "Version"));
    SetVerify(GetConfString(conf, NULL, "CertificateVerify"));
    SetCipherSuite(GetConfString(conf, NULL, "CipherSuite"));

    LoadCACert(GetConfString(conf, NULL, "CAFile"));
    LoadCRLFile(GetConfString(conf, NULL, "CRLFile"));
    // optional own cert and own prk
    char * file = GetConfString(conf, NULL, "OwnCert");
    if (strcmp(file, ""))
        LoadOwnCert(file);
    file = GetConfString(conf, NULL, "OwnPrivateKey");
    if (strcmp(file, ""))
        LoadOwnPrivateKey(file);

    char * acc_san_str = GetConfString(conf, NULL, "AcceptableSubjectAltName");
    char * pch = strtok (acc_san_str, "|");
    while (pch) {
        acc_san_.push_back(string(pch));
        pch = strtok(NULL, "|");
    }
}

void EasySSL_CTX::SetVersion(const char * version) {
    version_ = version;
    printf("Version: %s\n", version);
    if (!strcmp(version, "SSLv3_client")) {
        ctx_ = SSL_CTX_new(SSLv3_client_method());
    } else if (!strcmp(version, "TLSv1_client")) {
        ctx_ = SSL_CTX_new(TLSv1_client_method());
    } else if (!strcmp(version, "TLSv1.1_client")) {
        ctx_ = SSL_CTX_new(TLSv1_1_client_method());
    } else if (!strcmp(version, "TLSv1.2_client")) {
        ctx_ = SSL_CTX_new(TLSv1_2_client_method());
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
    } else if (!strcmp(version, "TLSv1.2_server")) {
        ctx_ = SSL_CTX_new(TLSv1_2_server_method());
        SSL_CTX_set_options(ctx_, SSL_OP_SINGLE_DH_USE);
        SSL_CTX_set_tmp_dh_callback(ctx_, tmp_dh_callback);
    } else if (!strcmp(version, "Compatible_server")) {
        ctx_ = SSL_CTX_new(SSLv23_server_method());
        SSL_CTX_set_options(ctx_, SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
        SSL_CTX_set_tmp_dh_callback(ctx_, tmp_dh_callback);
    } else {
        HANDLE_ERROR("** illegal SSL/TLS version!");
    }
    SSL_CTX_set_mode(ctx_, SSL_MODE_AUTO_RETRY);
}

void EasySSL_CTX::SetVerify(const char * verify) {
    verify_ = verify;
    int mode;
    if (!strcmp(verify, "AUTH_NONE"))
        mode = SSL_VERIFY_NONE;
    if (!strcmp(verify, "AUTH_REQUEST"))
        mode = SSL_VERIFY_PEER;
    if (!strcmp(verify, "AUTH_REQUIRE"))
        mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    SSL_CTX_set_verify(ctx_, mode, NULL);
}

void EasySSL_CTX::SetCipherSuite(const char * cipher_list) {
    cipher_suite_ = cipher_list;
    if (SSL_CTX_set_cipher_list(ctx_, cipher_list) != 1)
        HANDLE_ERROR("Error setting cipher list (no valid ciphers)");
}

// On success, the function returns 1, otherwise fail.
void EasySSL_CTX::LoadCACert(const char * cA_filename) {
    if (cA_filename == NULL || !strcmp(cA_filename, ""))  // empty filename
        HANDLE_ERROR("Error loading CA file, because the CA certificate filename is empty");
    if (SSL_CTX_load_verify_locations(ctx_, cA_filename, NULL) != 1)
        HANDLE_ERROR("Error loading CA file");
    cA_file_ = cA_filename;
    // load the CA cert into cert store
    if (X509_STORE_load_locations(x509_store_, cA_file_, NULL) != 1)
        HANDLE_ERROR("Error loading the CA file into cert store");
}

void EasySSL_CTX::LoadCRLFile(const char * cRL_file) {
    cRL_file_ = "crl.pem";
    if (cRL_file == NULL || !strcmp(cRL_file, "")) {
        fprintf(stderr, "The CRL filename is empty. Using the default CRL filename \"crl.pem\"");
    } else {
        cRL_file_ = cRL_file;
    }
    // load the CRL into the cert store
    X509_LOOKUP * lookup;
    // create a X509_LOOKUP object, add to the store, assign the lookup the CRL file
    if (!(lookup = X509_STORE_add_lookup(x509_store_, X509_LOOKUP_file())))
        HANDLE_ERROR("Error creating X509_LOOKUP object");
    // If there is no local crl file.
    if (X509_load_crl_file(lookup, cRL_file_, X509_FILETYPE_PEM) != 1) {
        fprintf(stderr, "No local CRL file. Trying to download CRL from the crlDistributionPoint extension in the CA certificate\n");
        // get the cdp extension in the CA cert
        char * cdp_uri = GetCrlDistributionPointURI(cA_file_);
        if (!cdp_uri)
            HANDLE_ERROR("Error reading crlDistributionPoint from CA certificate");
        // download crl file with the URI
        if (RetrieveFileviaHTTP(cdp_uri, cRL_file_)) {
            fprintf(stderr, "CRL file downloaded.\n");
            if (X509_load_crl_file(lookup, cRL_file_, X509_FILETYPE_PEM) != 1)
                HANDLE_ERROR("Error add the downloaded CRL file to cert store");
        } else {
            fprintf(stderr, "Fail to download CRL via HTTP\n");
            HANDLE_ERROR("Error downloading CRL");
        }
    }
    X509_STORE_set_flags(x509_store_, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
}

// On success, the function returns 1, otherwise fail.
void EasySSL_CTX::LoadOwnCert(const char * cert_filename) {
    own_cert_file_ = cert_filename;
    if (cert_filename == NULL || !strcmp(cert_filename, ""))
        HANDLE_ERROR("Error loading own certificate, because the certicate filename is empty");
    if (SSL_CTX_use_certificate_chain_file(ctx_, cert_filename) != 1)
        HANDLE_ERROR("Error loading own certificate from file");
}

// On success, the function returns 1, otherwise fail.
void EasySSL_CTX::LoadOwnPrivateKey(const char * private_key_filename) {
    own_prk_file_ = private_key_filename;
    if (private_key_filename == NULL || !strcmp(private_key_filename, ""))
        HANDLE_ERROR("Error loading private key, because the private key filename is empty");
    if (SSL_CTX_use_PrivateKey_file(ctx_, private_key_filename,
                                    SSL_FILETYPE_PEM) != 1)
        HANDLE_ERROR("Error loading private key from file");
}

void EasySSL_CTX::Set_acc_san(vector<string> acc_san) {
    acc_san_ = acc_san;
}

void EasySSL_CTX::LoadAccSanFromConfFile(const char * conf_filename) {
    long err = 0;
    CONF * conf = NCONF_new(NCONF_default());
    if (!NCONF_load(conf, conf_filename, &err)) {
        if (err == 0) {
            HANDLE_ERROR("Error opening configuration file");
        } else {
            fprintf(stderr, "Error in %s on line %li\n", conf_filename, err);
            HANDLE_ERROR("Errors parsing configuration file");
        }
    }
    
    char * acc_san_str = GetConfString(conf, NULL, "AcceptableSubjectAltName");
    char * pch = strtok (acc_san_str, "|");
    while (pch) {
        acc_san_.push_back(string(pch));
        pch = strtok(NULL, "|");
    }
}

void EasySSL_CTX::CreateListenSocket(const char * host_port) {
    bio_ = BIO_new_accept(const_cast<char *>(host_port));
    if (!bio_)
        HANDLE_ERROR("Error creating server socket");
    if (BIO_do_accept(bio_) <= 0)
        HANDLE_ERROR("Error binding server socket");
}

EasySSL * EasySSL_CTX::AcceptSocketConnection() {
    if (BIO_do_accept(bio_) <= 0)
        HANDLE_ERROR("Error accepting connection");
    BIO * client = BIO_pop(bio_);
    SSL * ssl;
    if (!(ssl = SSL_new(ctx_)))
        HANDLE_ERROR("Error creating new SSL");
    SSL_set_accept_state(ssl);
    SSL_set_bio(ssl, client, client);
    return new EasySSL(ssl, x509_store_, cA_file_, cRL_file_, acc_san_);
}

EasySSL * EasySSL_CTX::SocketConnect(const char * address) {
    BIO * bio = BIO_new_connect(const_cast<char *>(address));
    if (!bio)
        HANDLE_ERROR("Error creating connection BIO");
    if (BIO_do_connect(bio) <= 0)
        HANDLE_ERROR("Error connecting to remote machine");
    SSL * ssl = SSL_new(ctx_);
    if (!ssl)
        HANDLE_ERROR("Error creating new SSL");
    SSL_set_bio(ssl, bio, bio);
    return new EasySSL(ssl, x509_store_, cA_file_, cRL_file_, acc_san_);
}

//////////////////////////////////////////////////////////////////////
// EasySSL_CTX end
//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////
// EasySSL begin
//////////////////////////////////////////////////////////////////////

EasySSL::EasySSL(SSL * ssl, X509_STORE * x509_store, const char * cA_file, const char * cRL_file,
                 vector<string> acc_san) {
    ssl_ = ssl;
    x509_store_ = x509_store;
    cA_file_ = cA_file;
    cRL_file_ = cRL_file;
    acc_san_ = acc_san;
}

void EasySSL::SSLAccept(const char * host) {
    if (SSL_accept(ssl_) <= 0)
        HANDLE_ERROR("Error accepting SSL connection");
    if (!CRLCheck())
        HANDLE_ERROR("Error checking peer certificate against CRL");
    long post_err;
    if ((post_err = SANCheck(host)) != X509_V_OK) {
        fprintf(stderr, "-Error: peer certificate: %s\n",
            X509_verify_cert_error_string(post_err));
        HANDLE_ERROR("Error checking SSL object after connection");
    }
}

void EasySSL::SSLConnect(const char * host) {
    if(SSL_connect(ssl_) <= 0)
        HANDLE_ERROR("Error connecting SSL connection");
    if (!CRLCheck())
        HANDLE_ERROR("Error checking peer certificate against CRL");
    long post_err;
    if ((post_err = SANCheck(host)) != X509_V_OK) {
        fprintf(stderr, "-Error: peer certificate: %s\n",
            X509_verify_cert_error_string(post_err));
        HANDLE_ERROR("Error checking SSL object after connection");
    }
}

int EasySSL::CRLCheck() {
    X509 * cert;
    X509_STORE_CTX * verify_ctx;

    // no peer cert, no check
    if (! (cert = SSL_get_peer_certificate(ssl_)))
        return 1;

    X509_CRL * crl = LoadCRL(cRL_file_);
    ASN1_TIME * next_update = X509_CRL_get_nextUpdate(crl);
    int day, sec;
    ASN1_TIME_diff(&day, &sec, NULL, next_update);
    // If the CRL expires, download it
    if (day < 0 || sec < 0) {
        // get the cdp extension in the CA cert
        char * cdp_uri = GetCrlDistributionPointURI(cA_file_);
        if (!cdp_uri)
            HANDLE_ERROR("Error reading crlDistributionPoint from CA certificate");
        // download crl file with the URI
        if (RetrieveFileviaHTTP(cdp_uri, cRL_file_)) {
            fprintf(stderr, "CRL file downloaded.\n");
            X509_LOOKUP * lookup;
            if (!(lookup = X509_STORE_add_lookup(x509_store_, X509_LOOKUP_file())))
                HANDLE_ERROR("Error creating X509_LOOKUP object");
            if (X509_load_crl_file(lookup, cRL_file_, X509_FILETYPE_PEM) != 1)
                HANDLE_ERROR("Error add the downloaded CRL file to cert store");
        } else {
            fprintf(stderr, "Fail to download CRL via HTTP\n");
            HANDLE_ERROR("Error downloading CRL");
        }
    }
    // create a verification context and initialize it
    if (!(verify_ctx = X509_STORE_CTX_new()))
        HANDLE_ERROR("Error creating X509_STORE_CTX object");
    if (X509_STORE_CTX_init(verify_ctx, x509_store_, cert, NULL) != 1)
        HANDLE_ERROR("Error initializing verification context");

    // verify the certificate, 1 on success, 0 on failure.
    return X509_verify_cert(verify_ctx);
}

long EasySSL::SANCheck(const char * host) {
    X509 * cert;
    
    // no peer cert, no check, return good
    if (! (cert = SSL_get_peer_certificate(ssl_)))
        return SSL_get_verify_result(ssl_);

    if (!acc_san_.size())
        HANDLE_ERROR("AcceptableSubjectAltName is empty. Can't authenticate the peer");

    STACK_OF(GENERAL_NAME) * san_names = NULL;
    san_names = (STACK_OF(GENERAL_NAME) *)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    // Check each name within the extension
    for (int i = 0; i < sk_GENERAL_NAME_num(san_names); i++) {
        const GENERAL_NAME * current = sk_GENERAL_NAME_value(san_names, i);
        char * value = NULL;
        switch (current->type) {
        case GEN_DNS:
            value = (char *)ASN1_STRING_data(current->d.dNSName);
            break;
        case GEN_EMAIL:
            value = (char *)ASN1_STRING_data(current->d.rfc822Name);
            break;
        }
        // verify subjectAltName against the host info of param
        if (host && value && !strcmp(host, value)) {
            return SSL_get_verify_result(ssl_);
        } else if (value && SANMatch(acc_san_, value)) {
            return SSL_get_verify_result(ssl_);
        }
    }
    X509_free(cert);
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    return X509_V_ERR_APPLICATION_VERIFICATION;
}

void EasySSL::Shutdown() {
    SSL_shutdown(ssl_);
    SSL_free(ssl_);
}

int EasySSL::Read(void * buf, int num) {
    int ret = SSL_read(ssl_, buf, num);
    
    switch (SSL_get_error(ssl_, ret)) {
        case SSL_ERROR_NONE:
            return ret;
            break;
        case SSL_ERROR_ZERO_RETURN:
            fprintf(stderr, "The TLS/SSL connection has been closed.\n");
            return ret;
            break;
        default:
            fprintf(stderr, "-Error: Unknown error occurred when performing the Read operation\n");
            return ret;
            break;
    }
}

int EasySSL::Write(const void * buf, int num) {
    int ret = SSL_write(ssl_, buf, num);
    switch (SSL_get_error(ssl_, ret)) {
        case SSL_ERROR_NONE:
            return ret;
            break;
        case SSL_ERROR_ZERO_RETURN:
            fprintf(stderr, "The TLS/SSL connection has been closed.\n");
            return ret;
            break;
        default:
            fprintf(stderr, "-Error: Unknown error occurred when performing the Write operation\n");
            return ret;
            break;
    }
}
