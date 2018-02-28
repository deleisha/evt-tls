#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>



#include <mbedtls/ssl.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"


typedef struct evt_config_s
{
    //all const chars are dynamically managed
    const char *ca_store;
    const char *crl_path;
    const char *cert_file;
    const char *key_file;
    const char *ciphers;

    int         cfg_err;
    uint32_t    protocols;
    uint32_t    transport; /* TCP or UDP - Default is TCP */
    uint32_t    verify_peer;
    int         ca_depth;
    int         use_count;

}evt_config_t;
static evt_config_t *evt_default;


typedef enum evt_endpt_t {
    ENDPT_IS_UNSPECIFIED
   ,ENDPT_IS_CLIENT
   ,ENDPT_IS_SERVER
}evt_endpt_t;


typedef struct evt_tls_s evt_tls_t;
typedef void (*evt_handshake_cb)( evt_tls_t *conn, int status);
/* generate this through macro when dtls need to be supported */
struct evt_tls_s {
    int                            tls_err;
    evt_endpt_t                    role;
    uint32_t                       state;

    void                           *user_data;

    evt_config_t                   *config;

    evt_handshake_cb               handshake_cb;


    mbedtls_entropy_context        entropy;
    mbedtls_ctr_drbg_context       ctr_drbg;
    mbedtls_ssl_context            ssl_conn;
    mbedtls_ssl_config             mconf;
    mbedtls_x509_crt               cert;
    mbedtls_pk_context             pkey;
};



typedef enum evt_error_t {
    EVT_ERR_NONE = 0

   ,EVT_ERR_NOMEM

   ,EVT_ERR_NO_KEYPAIR
   ,EVT_ERR_CIPHER_FAIL

   ,EVT_ERR_NOROLE
   ,EVT_ERR_HSHAKE_DONE
   ,EVT_ERR_NOCFG

   ,EVT_ERR_MAX_COUNT /* Don't add any entry after this line */
} evt_error_t;

const char *err_str[] = {
    "No error found"
   ,"Insufficient memory"
   ,"Cert or Key or Both required"
   ,"Cipher setting failed"
   ,"No role specified"
   ,"Handshake completed already"
   ,"Not configured yet"
};

void
evt_tls_set_err( evt_tls_t *tls, evt_error_t err)
{
    tls->tls_err = err;
}

evt_tls_t *evt_tls_new(void)
{
    evt_tls_t *tls = NULL;

    if ( (tls = calloc(1, sizeof(*tls))) == NULL) {
        return NULL;
    }
    
    tls->config = NULL;
    tls->tls_err = EVT_ERR_NONE;
    tls->role = ENDPT_IS_UNSPECIFIED;
    tls->state = 0;

    mbedtls_entropy_init(&tls->entropy);
    mbedtls_ctr_drbg_init(&tls->ctr_drbg);
    mbedtls_ssl_init(&tls->ssl_conn);
    mbedtls_ssl_config_init(&tls->mconf);
    mbedtls_x509_crt_init(&tls->cert);
    mbedtls_pk_init(&tls->pkey);

    return tls;
}

void evt_tls_free(evt_tls_t *tls)
{
    if ( tls == NULL) {
        return;
    }

    mbedtls_entropy_free(&tls->entropy);
    mbedtls_ctr_drbg_free(&tls->ctr_drbg);
    mbedtls_ssl_free(&tls->ssl_conn);
    mbedtls_ssl_config_free(&tls->mconf);
    mbedtls_x509_crt_free(&tls->cert);
    mbedtls_pk_free(&tls->pkey);

    free(tls);
}

evt_tls_t *evt_tls_client(void)
{
    evt_tls_t *client = NULL;

    if ((client = evt_tls_new()) == NULL) {
        return NULL;
    }

    client->role = ENDPT_IS_CLIENT;
    
    return client;
}

evt_tls_t *evt_tls_server(void)
{
    evt_tls_t *server = NULL;

    if ((server = evt_tls_new()) == NULL) {
        return NULL;
    }

    server->role = ENDPT_IS_SERVER;
    
    return server;
}

void evt_cfg_del( evt_config_t *cfg);
int evt_configure( evt_tls_t *tls, evt_config_t *cfg)
{
    if ( cfg == NULL) {
        cfg = evt_default;
    }

    evt_cfg_del(tls->config);
    tls->config = cfg;
    cfg->use_count++;

    return 0;
}

static int
set_mbedtls_config( evt_tls_t *tls)
{
    /* no check done as the caller already have checked these */
    int endpt = ENDPT_IS_SERVER ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;

    int transport = EVT_IS_TLS ? MBEDTLS_SSL_TRANSPORT_STREAM :
                    MBEDTLS_SSL_TRANSPORT_DATAGRAM;

    int preset;

    
    mbedtls_ssl_config_defaults(&tls->mconfig, endpt, transport, preset);

}


#define EVT_HANDSHAKE_COMPLETED                     (1 << 3)
int evt_tls_handshake(evt_tls_t *conn, evt_handshake_cb hcb)
{
    int rv = -1;

    if ( conn->role == ENDPT_IS_UNSPECIFIED ) {
        evt_tls_set_err(conn, EVT_ERR_NOROLE);
        goto err;
    }

    if ( conn->state & EVT_HANDSHAKE_COMPLETED) {
        evt_tls_set_err(conn, EVT_ERR_HSHAKE_DONE);
        goto err;
    }

    if ( conn->config == NULL) {
        evt_tls_set_err(conn, EVT_ERR_NOCFG);
        goto err;
    }

    conn->handshake_cb = hcb;

    if ( conn->role == ENDPT_IS_SERVER ) {
        //if (1) //accept
    }
    else {
        assert( conn->role == ENDPT_IS_CLIENT && "invalid role");
        //if (2) //connect
    }

    rv = 0;

err:
    return rv;
}

int evt_tls_connect(evt_tls_t *conn, evt_handshake_cb hcb)
{
    return evt_tls_handshake(conn, hcb);
}

int evt_tls_accept(evt_tls_t *conn, evt_handshake_cb hcb)
{
    return evt_tls_handshake(conn, hcb);
}


#define EVT_TLS_1_0                 (1 << 0)
#define EVT_TLS_1_1                 (1 << 1)
#define EVT_TLS_1_2                 (1 << 2)

#define EVT_PROTOCOLS_TLS_1         (EVT_TLS_1_0|EVT_TLS_1_1|EVT_TLS_1_2)

#define EVT_TLS_PROTOCOL_ALL        EVT_PROTOCOLS_TLS_1
#define EVT_TLS_DEFAULT_PROTOCOL    EVT_TLS_1_2


#define EVT_DEFAULT_CIPHERS   "TLSv1.2"


void
evt_cfg_set_err(evt_config_t *cfg, evt_error_t code)
{
    cfg->cfg_err = code;
}

const char *evt_cfg_strerror(const evt_config_t *cfg)
{
    return err_str[cfg->cfg_err];
}

int set_str( const char *src, const char **dest)
{
    int rv = -1;
    free((char *)*dest);

    if ( src != NULL) {
        if ((*dest = strdup(src)) == NULL) {
            goto err;
        }
    }
    rv = 0;

err:
    return rv;
}

int
evt_cfg_set_crtf_key(evt_config_t *cfg, const char *cert, const char *key)
{
    int rv = -1;

    if ( cert == NULL && key == NULL) {
        evt_cfg_set_err(cfg, EVT_ERR_NO_KEYPAIR);
        goto err;
    }

    if ( set_str(cert, &cfg->cert_file) != 0) {
        evt_cfg_set_err(cfg, EVT_ERR_NOMEM);
        goto err;
    }

    if ( set_str(key, &cfg->key_file) != 0) {
        evt_cfg_set_err(cfg, EVT_ERR_NOMEM);
        goto err;
    }

    rv = 0;

err:
    return rv;
}

int evt_cfg_set_ca_path( evt_config_t *cfg, char *ca_path)
{
    return set_str(ca_path, &cfg->ca_store);
}

int evt_cfg_set_crl_path( evt_config_t *cfg, char *crl_path)
{
    return set_str(crl_path, &cfg->ca_store);
}


int evt_cfg_set_ciphers(evt_config_t *cfg, char *ciphers)
{
    return set_str(ciphers, &cfg->ciphers);
}

void evt_cfg_set_protocols(evt_config_t *cfg, int proto)
{
    cfg->protocols = proto;
}


void evt_cfg_set_transport(evt_config_t *cfg, int transport)
{
    cfg->transport = transport;
}

#define EVT_VERIFY_NONE             (1 << 0)
#define EVT_VERIFY_OPTIONAL         (1 << 1)
#define EVT_VERIFY_REQUIRED         (1 << 2)


void evt_cfg_set_verify(evt_config_t *cfg, int mode)
{
    cfg->verify_peer = mode;
}


void evt_cfg_del( evt_config_t *cfg)
{
    if (cfg == NULL) return;

    if (--cfg->use_count > 0) return;

    free((void*)cfg->ca_store);
    free((void*)cfg->crl_path);
    free((void*)cfg->cert_file);
    free((void*)cfg->key_file);
    free((void*)cfg->ciphers);
    free(cfg);
    cfg = NULL;
}

#define EVT_IS_TLS    1
#define EVT_IS_DTLS   2



evt_config_t* evt_cfg_new(void)
{
    evt_config_t *cfg = NULL;

    if ( (cfg = calloc(1, sizeof(*cfg))) == NULL )
    {
        goto err;
    }

    cfg->cfg_err = EVT_ERR_NONE;
    cfg->use_count = 1;

    if ( evt_cfg_set_ciphers(cfg, "TLS1.2") != 0) {
        goto err;
    }

    evt_cfg_set_protocols(cfg, EVT_TLS_DEFAULT_PROTOCOL);

    evt_cfg_set_transport(cfg, EVT_IS_TLS);

    evt_cfg_set_verify(cfg, EVT_VERIFY_REQUIRED);

    cfg->ca_depth = 5;

    return cfg;

err:
    evt_cfg_del(cfg);
    cfg = NULL;
    return NULL;
}

int evt_init(void)
{
    if (evt_default) return 0;

    if ( (evt_default = evt_cfg_new()) == NULL ) {
        return -1;
    }

    return 0;
}


evt_config_t *evt_default_cfg(void)
{
    if (evt_default != NULL) {
        return evt_default;
    }

    if ( (evt_default = evt_cfg_new()) == NULL) {
        return NULL;
    }

    return evt_default;
}


int main()
{
    evt_config_t *cfg = NULL;

    cfg = evt_default_cfg();
    assert(cfg != NULL && "test failed");
    assert( cfg == evt_default && "test failed");
    assert( 1 == cfg->use_count && "test failed");
    assert( (cfg->verify_peer == EVT_VERIFY_REQUIRED) && "test failed");
    assert( (cfg->transport == EVT_IS_TLS) && "test failed");
    assert( (cfg->protocols == EVT_TLS_DEFAULT_PROTOCOL) && "test failed");
    assert( (strcasecmp(cfg->ciphers, "TLS1.2") == 0) && "test failed");

    cfg = evt_cfg_new();
    assert(cfg != NULL && "test failed");
    assert( cfg != evt_default && "test failed");
    assert( 1 == cfg->use_count && "test failed");
    assert( (cfg->verify_peer == EVT_VERIFY_REQUIRED) && "test failed");
    assert( (cfg->transport == EVT_IS_TLS) && "test failed");
    assert( (cfg->protocols == EVT_TLS_DEFAULT_PROTOCOL) && "test failed");
    assert( (strcasecmp(cfg->ciphers, "TLS1.2") == 0) && "test failed");

    evt_cfg_del(cfg);

    //test the same thing after calling evt_init()
    assert( evt_init() == 0 && "test failed");

    cfg = evt_default_cfg();
    assert(cfg != NULL && "test failed");
    assert( cfg == evt_default && "test failed");
    assert( 1 == cfg->use_count && "test failed");
    assert( (cfg->verify_peer == EVT_VERIFY_REQUIRED) && "test failed");
    assert( (cfg->transport == EVT_IS_TLS) && "test failed");
    assert( (cfg->protocols == EVT_TLS_DEFAULT_PROTOCOL) && "test failed");
    assert( (strcasecmp(cfg->ciphers, "TLS1.2") == 0) && "test failed");

    cfg = evt_cfg_new();
    assert(cfg != NULL && "test failed");
    assert( cfg != evt_default && "test failed");
    assert( 1 == cfg->use_count && "test failed");
    assert( (cfg->verify_peer == EVT_VERIFY_REQUIRED) && "test failed");
    assert( (cfg->transport == EVT_IS_TLS) && "test failed");
    assert( (cfg->protocols == EVT_TLS_DEFAULT_PROTOCOL) && "test failed");
    assert( (strcasecmp(cfg->ciphers, "TLS1.2") == 0) && "test failed");

    evt_cfg_del(cfg);

    printf("Test passed\n");
}
