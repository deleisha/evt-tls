#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/certs.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#include <string.h>

typedef struct evt_tls_t
{
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
} evt_tls_t;



#define mbedtls_printf printf
#define MBEDTLS_DEBUG_LEVEL 4
const char * pers = "test mbedtls server";
void my_debug()
{
}



void handshake_cb(evt_tls_t *evt, int status)
{
    printf("Evt: Handshake done\n");

}


void evt_tls_init(evt_tls_t *evt)
{
    mbedtls_net_init( &(evt->server_fd) );
    mbedtls_entropy_init( &(evt->entropy) );
    mbedtls_ssl_init( &(evt->ssl) );
    mbedtls_ssl_config_init( &(evt->conf) );
    mbedtls_ctr_drbg_init( &(evt->ctr_drbg) );
    mbedtls_x509_crt_init( &(evt->srvcert) );
    mbedtls_pk_init( &(evt->pkey) );
}

void evt_tls_deinit(evt_tls_t *evt)
{
    mbedtls_net_free( &(evt->server_fd) );
    mbedtls_ssl_free( &(evt->ssl) );
    mbedtls_ssl_config_free( &(evt->conf) );
    mbedtls_ctr_drbg_free( &(evt->ctr_drbg) );
    mbedtls_entropy_free( &(evt->entropy) );
    mbedtls_x509_crt_free( &(evt->srvcert) );
    mbedtls_pk_free( &(evt->pkey) );
}
typedef void (evt_handshake_cb)(evt_tls_t *, int status);

int evt_tls_connect(evt_tls_t *evt, evt_handshake_cb hshake_cb)
{
    int ret  = 0;
    if( mbedtls_ssl_config_defaults( &(evt->conf),
            MBEDTLS_SSL_IS_SERVER,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT ) 
       )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        return -1;
    }

    mbedtls_ssl_conf_rng( &(evt->conf), mbedtls_ctr_drbg_random, &(evt->ctr_drbg) );
    mbedtls_ssl_conf_dbg( &(evt->conf), my_debug, stdout );

    if( mbedtls_ssl_setup( &(evt->ssl),&(evt->conf) ) )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        return -1;
    }

    while( (ret = mbedtls_ssl_handshake( &(evt->ssl)) ))
    {
        
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            char err[1024] = {0};
            mbedtls_strerror(ret, err, sizeof(err));
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned: %s\n\n", err );
        }
    }
    if ( ret == 0 && (evt->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) ) {
            //call handshake cb
            hshake_cb( evt, ret);
    }
    return ret;
}



int main()
{
    unsigned char buf[1024] = {0};
    mbedtls_net_context client_fd;
    int ret = 0;
    int len = 0;
    evt_tls_t evt;
    evt_tls_init(&evt);
    mbedtls_net_init( &client_fd );

    ret = mbedtls_x509_crt_parse( &(evt.srvcert), (const unsigned char *) mbedtls_test_srv_crt,
                          mbedtls_test_srv_crt_len);
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret = mbedtls_x509_crt_parse( &evt.srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret =  mbedtls_pk_parse_key( &(evt.pkey), (const unsigned char*) mbedtls_test_srv_key,
                         mbedtls_test_srv_key_len, NULL, 0  );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    if( mbedtls_net_bind( &(evt.server_fd), NULL, "4433", MBEDTLS_NET_PROTO_TCP ))
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
        goto exit;
    }

    if( mbedtls_ctr_drbg_seed( &(evt.ctr_drbg), mbedtls_entropy_func, &(evt.entropy),
                (const unsigned char *) pers,
                strlen(pers) ) )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    mbedtls_ssl_conf_ca_chain( &(evt.conf), evt.srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &(evt.conf), &(evt.srvcert), &(evt.pkey) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        goto exit;
    }

    
    mbedtls_net_free( &client_fd );

    //Find out why it crashes
    //mbedtls_ssl_session_reset( &(evt.ssl) );

    /*
     * 3. Wait until a client connects
     */
    mbedtls_printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_accept( &(evt.server_fd), &client_fd,
                                    NULL, 0, NULL ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &(evt.ssl), &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    mbedtls_printf( " ok\n" );

    /*
     * 5. Handshake
     */
    evt_tls_connect(&evt, handshake_cb);

    
    mbedtls_printf( " ok\n" );

    /*
     * 6. Read the HTTP Request
     */
    mbedtls_printf( "  < Read from client:" );
    fflush( stdout );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &(evt.ssl), buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf( " connection was closed gracefully\n" );
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf( " connection was reset by peer\n" );
                    break;

                default:
                    mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
                    break;
            }

            break;
        }

        len = ret;
        mbedtls_printf( " %d bytes read\n\n%s", len, (char *) buf );

        if( ret > 0 )
            break;
    }
    while( 1 );

exit:
return 0;
}
