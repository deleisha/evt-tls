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

#define mbedtls_printf printf


//supported TLS operation
enum tls_op_type {
    EVT_TLS_OP_HANDSHAKE
   ,EVT_TLS_OP_READ
   ,EVT_TLS_OP_WRITE
   ,EVT_TLS_OP_SHUTDOWN
};
typedef struct evt_tls_s evt_tls_t;
typedef void (*evt_handshake_cb)(evt_tls_t *, int status);

enum evt_endpt_t {
    ENDPT_IS_CLIENT
   ,ENDPT_IS_SERVER
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
    unsigned char nio_data[16*1024];
    int nio_data_len;
    int offset;
};

char *role[] = {
    "Client",
    "Server"
};


evt_endpt_t evt_tls_get_role(const evt_tls_t *t)
{
    return (evt_endpt_t)t->ssl.conf->endpoint;
}


typedef struct nio_data
{
    unsigned char scratch[16*1024];
    int scratch_len;
    int is_stalled;
}nio_data;

nio_data ndata;


int my_send(void *ctx, const unsigned char *buf, size_t len)
{
    evt_tls_t *tls = (evt_tls_t*)ctx;
    evt_tls_t* self = (evt_tls_t*)tls->data;
    mbedtls_printf("%s: Sending %u bytes\n",role[evt_tls_get_role(self)], len);
//    if (ndata.is_stalled ) {
 //       return MBEDTLS_ERR_SSL_WANT_WRITE;
//
 //   }
    memcpy(tls->nio_data, buf, len);
    tls->nio_data_len = len;
    tls->offset = 0;
    return len;
}

int my_recv(void *ctx, unsigned char *buf, size_t len)
{
    evt_tls_t* tls = (evt_tls_t*)ctx;
    evt_tls_t* self = (evt_tls_t*)tls->data;
    mbedtls_printf("%s : reading %u bytes\n",role[evt_tls_get_role(self)],len );
    if (self->nio_data_len < len ) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    memcpy( buf, self->nio_data + self->offset, len);
    self->nio_data_len -= len;
    self->offset +=len;
    return len;
}

static void mimic_asyncio(evt_tls_t *self, evt_tls_t *peer)
{
//    if (self->state != MBEDTLS_SSL_HANDSHAKE_OVER )
    {
//        evt__tls__op(self,  EVT_TLS_OP_HANDSHAKE, NULL, 0);
    }
}

static int evt__tls__op(evt_tls_t *conn, enum tls_op_type op, void *buf, int sz)
{
    int r = 0;
    switch ( op ) {
        case EVT_TLS_OP_HANDSHAKE: {
            if ( conn->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
            {
                r = mbedtls_ssl_handshake_step(&(conn->ssl));
                if( (r < 0 ))
                {
                    char err[1024] = {0};
                    mbedtls_strerror(r, err, sizeof(err));
                    mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned: %s\n\n", err );
                }

                if ( conn->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER)
                {
                    conn->hshake_cb(conn, r);
                }
                break;
            }
        }

        case EVT_TLS_OP_READ: {
        }

        case EVT_TLS_OP_WRITE: {
            break;
        }

        case EVT_TLS_OP_SHUTDOWN: {
            break;
        }

        default:
            break;
    }
    return r;
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

//    while( (ret = mbedtls_ssl_handshake( &(evt->ssl)) ))
//    {
//        
//        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
//        {
//            char err[1024] = {0};
//            mbedtls_strerror(ret, err, sizeof(err));
//            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned: %s\n\n", err );
//        }
//    }
//    if ( ret == 0 && (evt->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) ) {
//            hshake_cb( evt, ret);
//    }
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
    unsigned char buf[1024] = {0};
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
    mbedtls_ssl_conf_ca_chain( &(client_hdl.conf), &(client_hdl.srvcert), NULL );

    mbedtls_ssl_set_bio( &(client_hdl.ssl), &svc_hdl, my_send, my_recv, NULL);

    evt_tls_connect(&client_hdl, handshake_cb);


    //Start the handshake now
    evt_tls_accept(&svc_hdl, handshake_cb);

    //client send ClientHello
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //Server recieves hello messsage
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);
    //Server respond with ServerHello
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);
    //cleint parses ServerHello
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //Write ServerCert
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //client parses server certs
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //Server wrote ServerKeyExchnge
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //client parses server key
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //server sends certRequest, nothing if verification mode is off
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //Sends serverHelloDone
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //parses cert request
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //parses server Hello done
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //send client cert 
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);


    //send client key
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //parses client cert
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //parses client key
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //handles certificate verify
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //parses certificate verify
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //send cipher change spec
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //parses cipher change spec
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //write client finishes
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //parses client finishes
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //send change server cipher spec
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //parses server change cipher spec
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);


    //send server finishes
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //parses server finishes
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);


    //wrapup - flush buffer
    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);


    //parses server finishes
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);



    r = evt__tls__op(&svc_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

    //parses server finishes
    r = evt__tls__op(&client_hdl, EVT_TLS_OP_HANDSHAKE, 0, 0);
    assert(r == 0);

//    /*
//     * 6. Read the HTTP Request
//     */
//    mbedtls_printf( "  < Read from client:" );
//    fflush( stdout );
//
//    do
//    {
//        len = sizeof( buf ) - 1;
//        memset( buf, 0, sizeof( buf ) );
//        r = mbedtls_ssl_read( &(svc_hdl.ssl), buf, len );
//
//        if( r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE )
//            continue;
//
//        if( r <= 0 )
//        {
//            switch( r )
//            {
//                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
//                    mbedtls_printf( " connection was closed gracefully\n" );
//                    break;
//
//                case MBEDTLS_ERR_NET_CONN_RESET:
//                    mbedtls_printf( " connection was reset by peer\n" );
//                    break;
//
//                default:
//                    mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -r );
//                    break;
//            }
//
//            break;
//        }
//
//        len = r;
//        mbedtls_printf( " %d bytes read\n\n%s", len, (char *) buf );
//
//        if( r > 0 )
//            break;
//    } while( 1 );
}
