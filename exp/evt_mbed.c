#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

#include "evt_mbed.h"


static int set_str( const char *src, const char **dest)
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



evt_error_t
evt_tls_get_err(const evt_tls_t *tls)
{
    return tls->tls_err;
}

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


static evt_config_t *evt_default;

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

static
int my_send(void *ctx, const unsigned char *buf, size_t len)
{
//    evt_tls_t *tls = (evt_tls_t*)ctx;
//    evt_tls_t* self = (evt_tls_t*)tls->data;
//    if (tls->nio_data_len) {
//        return MBEDTLS_ERR_SSL_WANT_WRITE;
//    }
//    memcpy(tls->nio_data, buf, len);
//    tls->nio_data_len = len;
//    tls->offset = 0;
//    return len;
}

static
int my_recv(void *ctx, unsigned char *buf, size_t len)
{
//    evt_tls_t* tls = (evt_tls_t*)ctx;
//    evt_tls_t* self = (evt_tls_t*)tls->data;
//    if (self->nio_data_len < len ) {
//        return MBEDTLS_ERR_SSL_WANT_READ;
//    }
//    memcpy( buf, self->nio_data + self->offset, len);
//    self->nio_data_len -= len;
//    self->offset +=len;
//    return len;
}

static int
configure_mbedtls( evt_tls_t *tls )
{
    /* No input check done as caller should have done that */
    int rv = -1;
    evt_config_t *ecfg = tls->config;
    mbedtls_ssl_config *mcfg = &tls->mconf;
    assert(tls->role == ENDPT_IS_SERVER ||  tls->role == ENDPT_IS_CLIENT);

    if ( ecfg->ca_store == NULL ) {
        if (tls->get_ca_cert) {
            /*get_ca_cert to return platform specific default ca_certs file */
            //make this as new API
            const char *str = tls->get_ca_cert(tls);
            if (set_str(str, &ecfg->ca_file) != 0 ) {
                evt_tls_set_err(tls, EVT_ERR_NOMEM);
                goto err;
            }

            if (mbedtls_x509_crt_parse_file(&tls->ca_certs, ecfg->ca_file) != 0)
            {
                evt_tls_set_err(tls, EVT_ERR_BADCERT);
                goto err;
            }
        }
    }
    else {
        if ( mbedtls_x509_crt_parse_path(&tls->ca_certs, ecfg->ca_store) != 0) {
            evt_tls_set_err(tls, EVT_ERR_BADCERT);
            goto err;
        }
    }

    /* no check done as the caller already have checked these */
    int transport = (ecfg->transport == EVT_IS_TLS) ?
                        MBEDTLS_SSL_TRANSPORT_STREAM :
                            MBEDTLS_SSL_TRANSPORT_DATAGRAM;

    int endpt = (tls->role == ENDPT_IS_SERVER) ?
                    MBEDTLS_SSL_IS_SERVER :
                        MBEDTLS_SSL_IS_CLIENT;

    /* TODO: get the version from ecfg->protocols through a function */
    mbedtls_ssl_conf_min_version(mcfg,
        MBEDTLS_SSL_MAJOR_VERSION_3,
        MBEDTLS_SSL_MINOR_VERSION_2);

    /*make sure that all the defaults are loaded, cipher we overwrite next*/
    if (mbedtls_ssl_config_defaults(
        mcfg,
        endpt,
        transport,
        MBEDTLS_SSL_PRESET_DEFAULT
       ) != 0) {
        evt_tls_set_err(tls, EVT_ERR_NOMEM);
        goto err;
    }

    /* TODO : using the default, need to make configurable */
    //mbedtls_ssl_conf_ciphersuites(&mcfg, my_ciphers);


    mbedtls_ssl_conf_authmode(mcfg, ecfg->verify_peer);
    /* ca_depth is hardcoded in mbedtls and hence ignored  */

    if (mbedtls_ctr_drbg_seed(&(tls->ctr_drbg),
                mbedtls_entropy_func,
                &(tls->entropy),
                (const unsigned char *) "evt seeding",
                sizeof("evt seeding") 
       ) != 0)  {
        evt_tls_set_err(tls, EVT_ERR_ESEED);
        goto err;
    }

    mbedtls_ssl_set_bio( &(tls->ssl_conn), tls, my_send, my_recv, NULL);
    
    rv = 0;

err:
    return rv;
}


int evt_tls_is_handshake_done(const evt_tls_t *conn)
{
    return conn->ssl_conn.state == MBEDTLS_SSL_HANDSHAKE_OVER;
}

int evt_tls_handshake(evt_tls_t *conn, evt_handshake_cb hcb)
{
    int rv = -1;

    if ( conn->config == NULL) {
        evt_tls_set_err(conn, EVT_ERR_NOCFG);
        goto err;
    }

    if ( conn->role == ENDPT_IS_UNSPECIFIED ) {
        evt_tls_set_err(conn, EVT_ERR_NOROLE);
        goto err;
    }

    if ( conn->state & EVT_HANDSHAKE_COMPLETED) {
        evt_tls_set_err(conn, EVT_ERR_HSHAKE_DONE);
        goto err;
    }

    if ( configure_mbedtls(conn) != 0 ) {
        goto err;
    }

    if ( conn->handshake_cb == NULL) {
        conn->handshake_cb = hcb;
    }

    if ( (rv = mbedtls_ssl_handshake_step(&conn->ssl_conn)) != 0 ) {
        if (rv == MBEDTLS_ERR_SSL_WANT_READ) {
            rv = EVT_NEED_READ;
            goto out;
        }
        if (rv == MBEDTLS_ERR_SSL_WANT_WRITE) {
            rv = EVT_NEED_FLUSH;
            goto out;
        }
        /* TODO: Do we need to reset the connection? */
        evt_tls_set_err(conn, EVT_ERR_HSHAKE);
        rv = -1;
        conn->handshake_cb(conn, rv);
        goto err;
    }

    /* check if handshake is done and trigger callback */
    if ( evt_tls_is_handshake_done(conn)) {
        conn->handshake_cb(conn, rv);
    }

    rv = 0;
out:
    return rv;

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




evt_error_t
evt_cfg_get_err(const evt_config_t *cfg)
{
    return cfg->cfg_err;
}

void
evt_cfg_set_err(evt_config_t *cfg, evt_error_t code)
{
    cfg->cfg_err = code;
}

const char *evt_cfg_strerror(const evt_config_t *cfg)
{
    return err_str[cfg->cfg_err];
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


