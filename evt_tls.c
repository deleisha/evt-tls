#include <assert.h>
#include "evt_tls.h"


//openssl 1.0.2 and later has SSL_is_server API to check 
//if the ssl connection is server or not
// Some older versions does not have this function.
// Hence this function is introduced.

// 0 - client
// 1 - server
int SSL_get_role(const SSL *s)
{
    return s->server;
}


static void tls_begin(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}


evt_tls_t *getSSL(evt_ctx_t *d_eng)
{
     evt_tls_t *con = malloc(sizeof(evt_tls_t));
     if ( !con ) {
	 return NULL;
     }
     memset( con, 0, sizeof *con);

     SSL *ssl  = SSL_new(d_eng->ctx);

     if ( !ssl ) {
	 return NULL;
     }
     con->ssl = ssl;

     //use default buf size for now.
     BIO_new_bio_pair(&(con->ssl_bio_), 0, &(con->app_bio_), 0);

     SSL_set_bio(con->ssl, con->ssl_bio_, con->ssl_bio_);

     QUEUE_INIT(&(con->q));
     QUEUE_INSERT_TAIL(&(d_eng->live_con), &(con->q));

     con->writer = d_eng->writer;

     return con;
}


void evt_tls_set_nio(evt_tls_t *c, int (*fn)(evt_tls_t *t, void *data, int sz))
{
    assert( c != NULL);
    c->writer = fn;
    assert(c->writer != NULL);
}


void evt_ctx_set_writer(evt_ctx_t *ctx, net_wrtr my_writer)
{
    assert(ctx != NULL);
    assert( ctx->writer == NULL);
    ctx->writer = my_writer;
    assert( ctx->writer != NULL);

}

int evt_ctx_set_crt_key(evt_ctx_t *tls, char *crtf, char *key)
{
    //SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_NONE, uv__tls_verify_peer);
    SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_NONE, NULL);

    int r = SSL_CTX_use_certificate_file(tls->ctx, crtf, SSL_FILETYPE_PEM);
    if(r != 1) {
        return -1;
    }
    tls->cert_set = 1;

    r = SSL_CTX_use_PrivateKey_file(tls->ctx, key, SSL_FILETYPE_PEM);
    if(r != 1) {
        return -1;
    }

    r = SSL_CTX_check_private_key(tls->ctx);
    if(r != 1) {
        return -1;
    }
    tls->key_set = 1;
    return 0;
}


int evt_ctx_init(evt_ctx_t *tls)
{
    tls_begin();

    //Currently we support only TLS, No DTLS
    tls->ctx = SSL_CTX_new(SSLv23_method());
    if(!tls->ctx) {
        return ENOMEM;
    }
    
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
    SSL_CTX_set_options(tls->ctx, options);

    SSL_CTX_set_mode(tls->ctx, SSL_MODE_AUTO_RETRY |
         SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER       |
         SSL_MODE_ENABLE_PARTIAL_WRITE             |
         SSL_MODE_RELEASE_BUFFERS
    );

    tls->cert_set = 0;
    tls->key_set = 0;
    tls->ssl_err_ = 0;
    tls->writer = NULL;

    QUEUE_INIT(&(tls->live_con));

    return 0;
}

int evt_ctx_is_crtf_set(evt_ctx_t *t)
{
    return t->cert_set && t->key_set;
}

int evt_ctx_is_key_set(evt_ctx_t *t)
{
    return t->key_set;
}

int evt_tls_feed_data(evt_tls_t *c, void *data, int sz)
{
    int rv =  BIO_write(c->app_bio_, data, sz);
    assert( rv == sz);

    //if handshake is not complete, do it again
    if (!SSL_is_init_finished(c->ssl)) {
	rv = evt__ssl_op(c, EVT_TLS_OP_HANDSHAKE, NULL, NULL);
    }
    else {
	char txt[16*1024] = {0};
	//char *txt = NULL;
	//rv = SSL_read(c->ssl, txt, sizeof(txt));
	int sz = sizeof(txt);
	rv = evt__ssl_op(c, EVT_TLS_OP_READ, txt, NULL);
	printf("%s", txt);
    }
    return rv;
}

int after__wrk(evt_tls_t *c, void *buf)
{
    int pending = BIO_pending(c->app_bio_);
    if ( !(pending > 0) )
	return 0;

    int p = BIO_read(c->app_bio_, buf, pending);
    assert(p == pending);

    if ( c->writer) {
	    c->writer(c, buf, p);
    }
    return p;
}

int evt__ssl_op(evt_tls_t *c, enum tls_op_type op, void *buf, int *sz)
{
    int r = 0;
    int bytes = 0;
    char tbuf[16*1024] = {0};

    switch ( op ) {
	case EVT_TLS_OP_HANDSHAKE: {
            r = SSL_do_handshake(c->ssl);
            bytes = after__wrk(c, tbuf);
	    if  (1 == r) {
		if (!SSL_get_role(c->ssl)) {
		    assert(c->connect_cb != NULL );
		    c->connect_cb(c, r);
	        }
	    }
	    break;
        }

        case EVT_TLS_OP_READ: {
            r = SSL_read(c->ssl, tbuf, sizeof(tbuf));
            bytes = after__wrk(c, tbuf);
	    if ( r > 0 ) {
                if( c->allocator) {
		    assert(c->read_cb != NULL);
                    c->allocator(c, r, buf);
		    memcpy(buf, tbuf, r);
                    c->read_cb(c, buf, r);
                }

		//adhoc code, XXX remove later
		memcpy(buf, tbuf, r);

            }

            break;
	}

	case EVT_TLS_OP_WRITE:
	r = SSL_write(c->ssl, buf, *sz);
	bytes = after__wrk(c, tbuf);
	if ( r > 0 ) {
	    if ( c->write_cb) {
		c->write_cb(c, r);
	    }
	}
	break;

	case EVT_TLS_OP_SHUTDOWN:
	r = SSL_shutdown(c->ssl);
	if ( r < 0 )
	    bytes = after__wrk(c, tbuf);
	break;

	default:
	assert( 0 && "Unsupported operation");
	break;
    }
    return r;
}

int evt_tls_connect(evt_tls_t *con, evt_conn_cb on_connect)
{
    con->connect_cb = on_connect;
    SSL_set_connect_state(con->ssl);
    return evt__ssl_op(con, EVT_TLS_OP_HANDSHAKE, NULL, NULL);
}

int evt_tls_accept( evt_tls_t *svc)
{
    assert(svc != NULL);
    SSL_set_accept_state(svc->ssl);
    return evt__ssl_op(svc, EVT_TLS_OP_HANDSHAKE, NULL, NULL);
//int evt_tls_feed_data(evt_tls_t *c, void *data, int sz)
}


int evt_tls_write(evt_tls_t *c, void *msg, int *str_len, evt_write_cb on_write)
{
    c->write_cb = on_write;
    return evt__ssl_op(c, EVT_TLS_OP_WRITE, msg, str_len);
}

// read only register the callback to be made
int evt_tls_read(evt_tls_t *c, evt_allocator allok, evt_read_cb on_read )
{
    assert(c != NULL);
    char *msg = NULL;
    c->allocator = allok;
    c->read_cb = on_read;
}


int evt_close();
int evt_force_close();
//clean up calls
