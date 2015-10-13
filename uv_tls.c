#include "uv_tls.h"
#include <assert.h>


int uv_tls_init(uv_loop_t *loop, evt_ctx_t *ctx, uv_tls_t *endpt)
{
    memset( endpt, 0, sizeof *endpt);

    assert(0 == uv_tcp_init(loop, &(endpt->skt)));

    evt_tls_t *t = evt_ctx_get_tls(ctx);
    assert( t != NULL );

    t->data = endpt;

    endpt->tls = t;
    endpt->tls_rd_cb = NULL;
    endpt->tls_cnct_cb = NULL;
    endpt->tls_cls_cb = NULL;
    endpt->tls_accpt_cb = NULL;
    return 0;
}



int uv_tls_connect(uv_tls_t *t, evt_conn_cb on_connect)
{
    return 0;
}
