#ifndef UV_TLS_H
#define UV_TLS_H

#ifdef __cpluplus
extern "C" {
#endif
#include "evt_tls.h"
#include "libuv/include/uv.h"

//copied gladly from libuv
#define CONTAINER_OF(ptr, type, member)                                       \
    ((type *) ((char *) (ptr) - offsetof(type, member)))


typedef struct uv_tls_s uv_tls_t;

typedef void (*uv_handshake_cb)(uv_tls_t*, int);

struct uv_tls_s {
   uv_tcp_t skt;
   evt_tls_t *tls;

   uv_read_cb tls_rd_cb;
   uv_close_cb tls_cls_cb;
   uv_handshake_cb tls_hsk_cb;
};

int uv_tls_init(uv_loop_t *loop, evt_ctx_t *ctx, uv_tls_t *endpt);

int uv_tls_accept(uv_tls_t *tls, uv_handshake_cb cb);
int uv_tls_read(uv_stream_t *tls, uv_alloc_cb alloc_cb , uv_read_cb on_read);
int uv_tls_close(uv_handle_t* session, uv_close_cb close_cb);


//int uv_tls_write(uv_write_t* req, uv_tls_t *client, uv_buf_t* buf, uv_write_cb cb);
//int uv_tls_connect(uv_tls_t *t, evt_conn_cb on_connect)
#ifdef __cpluplus
}
#endif //extern C

#endif //UV_TLS_H
