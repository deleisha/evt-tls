#include <stdio.h>
#include <assert.h>

#include "evt_tls.h"

typedef struct test_tls_s test_tls_t;

struct test_tls_s {
    evt_tls_t *endpts;
    test_tls_t *peer;
};

int test_tls_init(test_tls_t *tst_tls, evt_ctx_t *ctx)
{
    return 0;
}

struct my_data {
    char data[16*1024];
    int sz;
    int stalled;
}test_data;

void allok(evt_tls_t *tls, int sz, void *buf)
{
    buf = malloc(sz);
    assert(buf != NULL);
}

void on_read( evt_tls_t *tls, void *buf, int sz)
{
    printf("On_read called\n");

}

void on_write(evt_tls_t *tls, int status)
{
    assert(status > 0);
    printf("On_write called\n");
//    evt_tls_read( tls, allok, on_read);

}


void on_connect(evt_tls_t *tls, int status)
{
    int r = 0;
    if ( status ) {
	char msg[] = "Hello from event based tls engine\n";
	int str_len = sizeof(msg);
	r =  evt_tls_write(tls, msg, &str_len, on_write);

    }
}

//test nio_handler
//int test_net_rdr(test_tls_t *stream, void *bfr, int sz )
int test_net_wrtr(evt_tls_t *c, void *buf, int sz)
{
    //write to test data as simulation of network write
    memset(&test_data, 0, sizeof(test_data));
    memcpy(test_data.data, buf, sz);
    test_data.sz = sz;
    test_data.stalled = 0;
    return 0;
}

int test_net_rdr(test_tls_t *stream, void *bfr, int sz )
{
    int r = 0;
    if ( test_data.stalled ) {
	return r;
    }
    test_data.stalled = 1;
    r = evt_tls_feed_data(stream->endpts, bfr, sz); 
    return r;
}

int test_tls_connect(test_tls_t *t, evt_conn_cb on_connect)
{
    return evt_tls_connect(t->endpts, on_connect);
}



void on_accept(evt_tls_t *svc, int status)
{
    printf("On_accept called\n");
}

int test_tls_accept(test_tls_t *tls, evt_accept_cb on_accept)
{
//    process_recv_data(tls);
    return evt_tls_accept(tls->endpts, on_accept);

    return 0;
}

int main()
{

    evt_ctx_t tls;
    memset(&tls, 0, sizeof(tls));
    assert(0 == evt_ctx_init(&tls));


    assert(0 == evt_ctx_is_crtf_set(&tls));
    assert(0 == evt_ctx_is_key_set(&tls));
    
    if (!evt_ctx_is_crtf_set(&tls)) {
	evt_ctx_set_crt_key(&tls, "server-cert.pem", "server-key.pem");
    }

    assert( 1 == evt_ctx_is_crtf_set(&tls));
    assert( 1 == evt_ctx_is_key_set(&tls));


    assert(tls.writer == NULL);
    evt_ctx_set_writer(&tls, test_net_wrtr);
    assert(tls.writer != NULL);

    test_tls_t *clnt_hdl = malloc(sizeof *clnt_hdl);
    assert(clnt_hdl != 0);
    evt_tls_t *clnt = getSSL(&tls );

    clnt_hdl->endpts = clnt;


    evt_tls_t *svc = getSSL(&tls);
    SSL_set_accept_state(svc->ssl);
    test_tls_t *svc_hdl = malloc(sizeof(test_tls_t));
    assert(svc_hdl != 0);
    svc_hdl->endpts = svc;

    svc_hdl->peer = clnt_hdl;
    clnt_hdl->peer = svc_hdl;

    test_tls_connect(clnt_hdl, on_connect);
    test_tls_accept(svc_hdl, on_accept);

        
    free(clnt_hdl);
    free(svc_hdl);
    return 0;
}
