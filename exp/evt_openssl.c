#include <stdint.h>
#include <openssl/ssl.h>

// #if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
// ssl_ctx = SSL_CTX_new(TLS_client_method());
// #else
// ssl_ctx = SSL_CTX_new(SSLv23_client_method());
// #endif
//

#define EVT_TLS1_0                       (1 << 1)
#define EVT_TLS1_1                       (1 << 2)
#define EVT_TLS1_2                       (1 << 3)

#define EVT_PROTOCOLS_TLS1               (EVT_TLS1_0|EVT_TLS1_1|EVT_TLS1_2)

#define EVT_TLS_PROTOCOL_ALL             EVT_PROTOCOLS_TLS1
#define EVT_TLS_DEFAULT_PROTOCOL         EVT_TLS1_2


#define EVT_DEFAULT_CIPHERS   "TLSv1.2"

//certficate info for the connection
struct cert_info {
//    String    subjectName;
//    String    issuerName;
//    Uint32    depth;
//    Uint32    errorCode;
//    Uint32    respCode;
//    String    errorString;
//    Uint32    versionNumber;
//    long      serialNumber;
//    CIMDateTime    notBefore;
//    CIMDateTime    notAfter;
//    String    peerCertificate;
};


typedef struct keypair_t  {

        char *cert_mem;
        size_t cert_len;

        char *key_mem;
        size_t key_len;

        char *pubkey_hash;
        evt_kypr_t *next;
}evt_kypr_t;


typedef struct evt_config_t evt_config_t;
struct evt_config_t
{
    const char *ca_store;
    const char *crl_path;
    const char *cert_file;
    const char *key_file;
    const char *ciphers;
    uint32_t   protocols;
    uint32_t   verify_peer;
    int        ca_depth;
    int        use_count;
};

/* The APIs */
int evt_init(void);

void evt_config_free();

/* copied from libtls */
int set_string(const char **dest, const char *src)
{       
        free((char*) *dest);
        *dest = NULL;
        if ( src != NULL)
                if ((*dest = strdup(src)) == NULL)
                        return -1;
        return 0;
}

int evt_cfg_set_ciphers(evt_config_t *cfg, const char *ciphers)
{
    return set_string(&cfg->ciphers, ciphers);
}

void evt_cfg_set_protocols(evt_config_t *cfg, int protocols)
{
    cfg->protocols = protocols;
}


static evt_config_t* 
evt_config_new(void)
{
    evt_config_t *cfg;

    if ( (cfg = calloc(1, sizeof(*cfg))) == NULL) {
        return NULL;
    }
    cfg->use_count = 1;


    /*crl_path handling TBD */
    cfg->ca_store = NULL;
    cfg->crl_path = NULL;

    /* cert and key file handling */

    //ciphers
    if (evt_cfg_set_ciphers(cfg,EVT_DEFAULT_CIPHERS) != 0) {
        goto err;
    }

    evt_cfg_set_protocols(cfg, EVT_TLS_DEFAULT_PROTOCOL);
    /*
     * use either SSL_VERIFY_NONE or SSL_VERIFY_PEER, the last 2 options
     * are 'ored' with SSL_VERIFY_PEER if they are desired *
     #define SSL_VERIFY_NONE                 0x00
     #define SSL_VERIFY_PEER                 0x01
     #define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
     #define SSL_VERIFY_CLIENT_ONCE          0x04
    */
    cfg->verify_peer = 3;  /* This need to be made as API */
    cfg->ca_depth = 5; //Need API


    return cfg;

err:
    evt_config_free(cfg);
    return NULL;
}

void evt_config_free( evt_config_t *cfg)
{
    if (cfg == NULL) return;

    if (--cfg->use_count > 0 ) return;

    free((char*)cfg->ciphers);
    cfg->ciphers = NULL;

    free(cfg);
    cfg = NULL;
}



static evt_config_t *evt_default;


int evt_init(void)
{

    if (evt_default) {
        return 0;
    }

    SSL_load_error_strings();
    SSL_library_init();
    /*ERR_load_BIO_strings(); */
    /* TODO: do we need OpenSSL_add_all_algorithms(); */

    if ( (evt_default = evt_config_new()) == NULL) {
        return -1;
    }

    return 0;
}


int main()
{
    int rv = -1;
    if ( evt_init() != 0 ) {
        goto err;
    
    }
    evt_config_free(evt_default);
    return 0;

err:
    fprintf( stderr, "test failed \n");
    return -1;
}
