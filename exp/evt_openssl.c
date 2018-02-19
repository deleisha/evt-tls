#include <stdint.h>
#include <openssl/ssl.h>

// #if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
// ssl_ctx = SSL_CTX_new(TLS_client_method());
// #else
// ssl_ctx = SSL_CTX_new(SSLv23_client_method());
// #endif
//

#define EVT_TLS1_0    (1 << 1)
#define EVT_TLS1_1    (1 << 2)
#define EVT_TLS1_2    (1 << 3)

#define EVT_TLS1  (EVT_TLS1_0|EVT_TLS1_1|EVT_TLS1_2)

#define EVT_TLS_ALL EVT_TLS1
#define EVT_TLS_DEFAULT EVT_TLS1_2

//certficate info for the connection
struct cert_info {
    String    subjectName;
    String    issuerName;
    Uint32    depth;
    Uint32    errorCode;
    Uint32    respCode;
    String    errorString;
    Uint32    versionNumber;
    long      serialNumber;
    CIMDateTime    notBefore;
    CIMDateTime    notAfter;
#ifdef  PEGASUS_USE_EXPERIMENTAL_INTERFACES
    String    peerCertificate;
};


typedef struct evt_config_t evt_config_t;
struct evt_config_t {
    const char *ca_store;
    const char *crl_path;
    const char *cert_file;
    const char *key_file;
    const char *ciphers;
    uint32_t   protocols;
    uint32_t   verify_peer;
    int        ca_depth;
    int        ref_count;
};

int evt_init(void);

#defiene EVT_DEFAULT_CIPHERS   "TLSv1.2"

static evt_config_t* evt_cfg_new(void)
{
    evt_config_t *cfg;

    if ( (cfg = calloc(1, sizeof(*cfg))) == NULL) {
        return NULL;
    }

    /*crl_path handling TBD */
    cfg->ca_store = NULL;
    cfg->crl_path = NULL;

    /* cert and key file handling */

    //ciphers
    evt_config_set_ciphers(cfg, "default");
    evt_config_set_protocols(cfg, EVT_TLS_DEFAULT);
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

    if ( (evt_default = evt_cfg_new()) == NULL) {
        return -1;
    }

    return 0;
}


int main()
{
    return 0;
}
