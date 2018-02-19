#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/certs.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#define mbedtls_printf printf

#define EVT_WANT_POLLIN           -2
#define EVT_WANT_POLLOUT          -3


//supported TLS operation
enum tls_op_type {
    EVT_TLS_OP_HANDSHAKE
   ,EVT_TLS_OP_READ
   ,EVT_TLS_OP_WRITE
   ,EVT_TLS_OP_SHUTDOWN
};
typedef struct evt_tls_s evt_tls_t;
typedef void (*evt_handshake_cb)(evt_tls_t *, int status);
typedef void (*evt_write_cb)(evt_tls_t *, int status);
typedef void (*evt_read_cb)(evt_tls_t *con, const char *buf, int size);
typedef void (*evt_close_cb)(evt_tls_t *con, int status);

int evt_tls_read(evt_tls_t *c, evt_read_cb on_read );
int evt_tls_write(evt_tls_t *c, void *msg, int str_len, evt_write_cb on_write);

enum evt_endpt_t {
    ENDPT_IS_CLIENT
   ,ENDPT_IS_SERVER
};

typedef enum {
    EVT_ERR_NO_ERR = 0 /*No error occured/recorded */
    ,EVT_ERR_NO_MEM  /* No memory left or mem alloc failed */
    ,EVT_ERR_HSHAKE /* Handshake failed, ssl need to be reset*/
    ,EVT_ERR_WRITE /* TLS write failed, ssl need to be reset*/

    ,EVT_ERR_MAX
} evt_error_t;

const char * const evt_err_str[EVT_ERR_MAX] = {
    "No Memory left or alloc failed"
    ,"TLS handshake failed"
    ,"TLS write failed"
};

typedef enum evt_endpt_t evt_endpt_t;


struct evt_tls_s
{
    void *data;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
    evt_handshake_cb hshake_cb;
    evt_read_cb read_cb;
    evt_write_cb write_cb;
    evt_close_cb close_cb;

    //error handling
    int evt_error;

    unsigned char nio_data[16*1024];
    int nio_data_len;
    int offset;
};

char *role[] = {
    "Client",
    "Server"
};

evt_error_t evt_get_err( const evt_tls_t *evt)
{
    return evt->evt_error;
}

void evt_set_err( evt_tls_t *evt, int err_no )
{
    evt->evt_error = err_no;
}

void evt_clear_err(evt_tls_t *evt)
{
    evt->evt_error = EVT_ERR_NO_ERR;
}


const char *evt_strerr( const evt_tls_t *evt)
{
    return evt_err_str[evt->evt_error];
}

int evt_tls_is_handshake_done(const evt_tls_t *evt)
{
    return (evt->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER);
}


evt_endpt_t evt_tls_get_role(const evt_tls_t *t)
{
    return (evt_endpt_t)t->ssl.conf->endpoint;
}

static int
evt__tls__op(evt_tls_t *conn, enum tls_op_type op, void *buf, int sz)
{
    int r = -1;
    int offset = 0;
    unsigned char *bufr = NULL;
    char err[128] = {0};

    switch ( op ) {
        case EVT_TLS_OP_HANDSHAKE: {
            if ( !evt_tls_is_handshake_done(conn))
            {
                if ( (r = mbedtls_ssl_handshake_step(&(conn->ssl))) != 0 ) {
                    //ordering is important
                    if ( r == MBEDTLS_ERR_SSL_WANT_READ ||
                         r == MBEDTLS_ERR_SSL_WANT_WRITE)
                    {
                        break;
                    }

                    evt_set_err(conn, EVT_ERR_HSHAKE);
                    r = -1;

                    conn->hshake_cb(conn, r);
                }
                else {
                    if ( evt_tls_is_handshake_done(conn) )
                        conn->hshake_cb(conn, r);
                }
            }
            else {
                //handshake over, read instead
            }
            break;
        }

        case EVT_TLS_OP_READ: {
          break;
        }

        case EVT_TLS_OP_WRITE: {
           assert( conn->write_cb && "write cb not supplied");
           for( offset = 0; offset < sz; offset += r) {
               r = mbedtls_ssl_write(&conn->ssl,
                       (const unsigned char*)buf + offset, sz - offset
                   );
               if ( r == MBEDTLS_ERR_SSL_WANT_READ ||
                    r == MBEDTLS_ERR_SSL_WANT_WRITE)
               {
                    break;
               }
               if ( r < 0 ) {
                   evt_set_err(conn, EVT_ERR_WRITE);
                   r = -1;
                   conn->write_cb(conn, r);
                   break;
               }
           }
           if ( conn->write_cb ) {
               conn->write_cb(conn, sz);
           }
            break;
        }

        case EVT_TLS_OP_SHUTDOWN:
        default:
        assert( 0 && "Unsupported Operation Received");
        break;
    }
    return r;
}

int my_send(void *ctx, const unsigned char *buf, size_t len)
{
    evt_tls_t *tls = (evt_tls_t*)ctx;
    evt_tls_t* self = (evt_tls_t*)tls->data;
    if (tls->nio_data_len) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    memcpy(tls->nio_data, buf, len);
    tls->nio_data_len = len;
    tls->offset = 0;
    return len;
}

int my_recv(void *ctx, unsigned char *buf, size_t len)
{
    evt_tls_t* tls = (evt_tls_t*)ctx;
    evt_tls_t* self = (evt_tls_t*)tls->data;
    if (self->nio_data_len < len ) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    memcpy( buf, self->nio_data + self->offset, len);
    self->nio_data_len -= len;
    self->offset +=len;
    return len;
}

void on_close(evt_tls_t *evt, int status)
{
}

int evt_tls_close( evt_tls_t *conn, evt_close_cb on_close)
{
    int r = -1;
    conn->close_cb = on_close;

    evt_clear_err( conn );
    r = mbedtls_ssl_close_notify(&conn->ssl);

    if (r == MBEDTLS_ERR_SSL_WANT_READ)
        return EVT_WANT_POLLIN;
    if (r == MBEDTLS_ERR_SSL_WANT_WRITE)
        return EVT_WANT_POLLOUT;

    //handle error properly

    if ( conn->close_cb )
        conn->close_cb(conn, r);
    return (-1);
}



void on_read(evt_tls_t *evt, const char *buf, int len)
{
    mbedtls_printf("Read cb received msg: %s", buf);
    free((void*)buf);
}

int evt_tls_read(evt_tls_t *conn, evt_read_cb on_read)
{
    int rv = -1;
    size_t sz = 0;
    char *bufr = NULL;

    if ( evt_tls_get_role(conn) != ENDPT_IS_SERVER ||
         evt_tls_get_role(conn) != ENDPT_IS_CLIENT) {
        goto out;
    }

    if (!evt_tls_is_handshake_done(conn)) {
        //rv = evt_tls_ha
    }

    conn->read_cb = on_read;

    evt_clear_err( conn );
    rv = mbedtls_ssl_read(&conn->ssl, NULL, 0);
    if ( 0 == rv ) { // EOF
        conn->read_cb(conn, bufr, rv );
        rv = -1;
        goto out;
    }
    if (rv == MBEDTLS_ERR_SSL_WANT_READ)
        return EVT_WANT_POLLIN;
    if (rv == MBEDTLS_ERR_SSL_WANT_WRITE)
        return EVT_WANT_POLLOUT;

    sz = mbedtls_ssl_get_bytes_avail(&conn->ssl) + 1;

    bufr = calloc(1, sz);
    if ( !bufr ) {
        evt_set_err(conn, EVT_ERR_NO_MEM);
        rv = -1;
        goto out;
    }

    evt_clear_err( conn );
    rv = mbedtls_ssl_read( &conn->ssl, bufr, sz - 1);
    sz = ( rv > 0 ) ? (sz -1) : rv;

    if ( conn->read_cb ) {
        conn->read_cb(conn, (char*) bufr, sz);
    }
    return (-1);
out:
    return (rv);
}

void on_write(evt_tls_t *evt, int status)
{
    mbedtls_printf("write_cb: Data written\n");
}

int evt_tls_write(evt_tls_t *c, void *msg, int str_len, evt_write_cb on_write)
{
    assert( c != NULL);
    assert(msg != NULL && "Trying to write empty msg");
    c->write_cb = on_write;
    return evt__tls__op(c, EVT_TLS_OP_WRITE, msg, str_len); 
}

static void handshake_loop(evt_tls_t *src, evt_tls_t *dest)
{
    evt_tls_t *t = NULL;
    for(;;) {
        if ( !evt_tls_is_handshake_done(src)) {
            evt__tls__op(src,  EVT_TLS_OP_HANDSHAKE, NULL, 0);
        }
        else break;
        t = dest;
        dest= src;
        src = t;
    }
}


#define MBEDTLS_DEBUG_LEVEL 4
const char * pers = "test mbedtls server";
#define mbedtls_fprintf fprintf

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);
    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}


void handshake_cb(evt_tls_t *evt, int status)
{
    mbedtls_printf("%s: Handshake done\n",role[evt_tls_get_role(evt)]);
    char *str = "Hello ARM mbedtls";
    if ( 0 == status) {
        if (evt_tls_get_role(evt) == ENDPT_IS_CLIENT) {
            evt_tls_read(evt, on_read);
        }
        else 
        {
            evt_tls_write(evt, str, strlen(str), on_write);
        }
    }
}

void evt_tls_init(evt_tls_t *evt)
{
    mbedtls_entropy_init( &(evt->entropy) );
    mbedtls_ssl_init( &(evt->ssl) );
    mbedtls_ssl_config_init( &(evt->conf) );
    mbedtls_ctr_drbg_init( &(evt->ctr_drbg) );
    mbedtls_x509_crt_init( &(evt->srvcert) );
    mbedtls_pk_init( &(evt->pkey) );
    memset(evt->nio_data, 0, 16*1024);
    evt->nio_data_len = 0;
    evt->offset = 0;
}

void evt_tls_deinit(evt_tls_t *evt)
{
    mbedtls_ssl_free( &(evt->ssl) );
    mbedtls_ssl_config_free( &(evt->conf) );
    mbedtls_ctr_drbg_free( &(evt->ctr_drbg) );
    mbedtls_entropy_free( &(evt->entropy) );
    mbedtls_x509_crt_free( &(evt->srvcert) );
    mbedtls_pk_free( &(evt->pkey) );
}

int evt_tls_accept(evt_tls_t *evt, evt_handshake_cb hshake_cb)
{
    int ret  = 0;
    evt->hshake_cb = hshake_cb;
    if( mbedtls_ssl_config_defaults( &(evt->conf),
            MBEDTLS_SSL_IS_SERVER,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT )
       )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        return -1;
    }

    mbedtls_ssl_conf_rng(&(evt->conf),mbedtls_ctr_drbg_random,&(evt->ctr_drbg));
    mbedtls_ssl_conf_dbg( &(evt->conf), my_debug, stdout );
    mbedtls_ssl_conf_authmode( &(evt->conf), MBEDTLS_SSL_VERIFY_NONE );

    if( mbedtls_ssl_setup( &(evt->ssl),&(evt->conf) ) )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return -1;
    }

    evt__tls__op(evt,  EVT_TLS_OP_HANDSHAKE, NULL, 0);

    return ret;
}

int evt_tls_connect(evt_tls_t *evt, evt_handshake_cb hshake_cb)
{
    int ret  = 0;
    evt->hshake_cb = hshake_cb;
    if( mbedtls_ssl_config_defaults( &(evt->conf),
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT ) 
       )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        return -1;
    }

    mbedtls_ssl_conf_rng(&(evt->conf),mbedtls_ctr_drbg_random,&(evt->ctr_drbg));
    mbedtls_ssl_conf_dbg( &(evt->conf), my_debug, stdout );
    mbedtls_ssl_conf_authmode( &(evt->conf), MBEDTLS_SSL_VERIFY_NONE );

    if( mbedtls_ssl_setup( &(evt->ssl), &(evt->conf) ) )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return -1;
    }

    ret = evt__tls__op(evt,  EVT_TLS_OP_HANDSHAKE, NULL, 0);

    return ret;
}

#define handle_error(r);   \
    if((r) != 0) {        \
        mbedtls_printf("failed\n ! mbedtls returned %d\n\n",r); \
        return 0;    \
    }

int main()
{
    int r = 0;
    int len = 0;
    evt_tls_t svc_hdl;
    evt_tls_t client_hdl;
    evt_tls_init(&svc_hdl);
    evt_tls_init(&client_hdl);
    svc_hdl.data = &client_hdl;
    client_hdl.data = &svc_hdl;
    mbedtls_debug_set_threshold(0);

    r = mbedtls_x509_crt_parse( &(svc_hdl.srvcert), (const unsigned char *) mbedtls_test_srv_crt,
                          mbedtls_test_srv_crt_len);
    handle_error(r);

    r = mbedtls_x509_crt_parse( &svc_hdl.srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    
    handle_error(r);


    r =  mbedtls_pk_parse_key( &(svc_hdl.pkey), (const unsigned char*) mbedtls_test_srv_key,
                         mbedtls_test_srv_key_len, NULL, 0  );
    
    handle_error(r);

    r = mbedtls_ctr_drbg_seed( &(svc_hdl.ctr_drbg), mbedtls_entropy_func, &(svc_hdl.entropy),
                (const unsigned char *) pers,
                strlen(pers) );
    handle_error(r);


    mbedtls_ssl_conf_ca_chain( &(svc_hdl.conf), svc_hdl.srvcert.next, NULL );
    r = mbedtls_ssl_conf_own_cert( &(svc_hdl.conf), &(svc_hdl.srvcert), &(svc_hdl.pkey) )
    handle_error(r);

    mbedtls_ssl_set_bio( &(svc_hdl.ssl), &client_hdl, my_send, my_recv, NULL);

    //
    //
    //Setup client part
    //
    r = mbedtls_x509_crt_parse( &(client_hdl.srvcert), (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    handle_error(r);

    r = mbedtls_ctr_drbg_seed( &(client_hdl.ctr_drbg), mbedtls_entropy_func, &(svc_hdl.entropy),
                (const unsigned char *) "Test client",
                sizeof("Test client") );
    handle_error(r);


    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode( &(client_hdl.conf), MBEDTLS_SSL_VERIFY_NONE );
    mbedtls_ssl_conf_ca_chain( &(client_hdl.conf), &(client_hdl.srvcert), NULL);

    mbedtls_ssl_set_bio( &(client_hdl.ssl), &svc_hdl, my_send, my_recv, NULL);

    evt_tls_connect(&client_hdl, handshake_cb);


    //Start the handshake now
    evt_tls_accept(&svc_hdl, handshake_cb);

    handshake_loop(&client_hdl, &svc_hdl);
}
