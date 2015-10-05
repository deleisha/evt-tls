#ifndef UV_TLS_H
#define UV_TLS_H

#ifdef __cpluplus
extern "C" {
#endif
#include "evt_tls.h"
#include "libuv/include/uv.h"
typedef struct uv_tls_s uv_tls_t;

struct uv_tls_s {
   uv_tcp_t skt;
   evt_tls_t *tls;
};

int uv_tls_init(uv_loop_t *loop, evt_ctx_t *ctx, uv_tls_t *endpt);

//int uv_tls_accept(uv_tls_t* client/*, call_back*/);
//int uv_tls_read(uv_tls_t* client, uv_alloc_cb alloc_cb , tls_rd_cb on_read);
//int uv_tls_write(uv_write_t* req, uv_tls_t *client, uv_buf_t* buf, uv_write_cb cb);
//int uv_tls_close(uv_tls_t* session, tls_close_cb close_cb);


//int uv_tls_connect(uv_tls_t *t, evt_conn_cb on_connect)
#ifdef __cpluplus
}
#endif //extern C

#endif //UV_TLS_H
