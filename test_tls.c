#include <assert.h>
#include "uv_tls.h"

void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    buf->base = (char*)malloc(size);
    memset(buf->base, 0, size);
    buf->len = size;
    assert(buf->base != NULL && "Memory allocation failed");
}

void on_write(evt_tls_t *tls, int status)
{
    uv_tls_close((uv_handle_t*)tls->data, (uv_close_cb)free);
}

int uv_tls_write(uv_tls_t *stream, uv_buf_t *buf, evt_write_cb cb)
{
    return evt_tls_write(stream->tls, buf->base, buf->len, cb);
}

void uv_rd_cb( uv_stream_t *strm, ssize_t nrd, const uv_buf_t *bfr)
{
    if ( nrd <= 0 )
        return;
    uv_tls_write((uv_tls_t*)strm, (uv_buf_t*)bfr, on_write);
}

void on_uv_handshake(uv_tls_t *ut, int status)
{
    if ( 0 == status ) {
        uv_tls_read((uv_stream_t*)ut, alloc_cb, uv_rd_cb);
    }
    else {
        uv_tls_close((uv_handle_t*)ut, (uv_close_cb)free);
    }
}

void on_connect_cb(uv_stream_t *server, int status)
{
    int r = 0;
    if( status ) {
        return;
    }
    //memory being freed at on_close
    uv_tls_t *sclient = malloc(sizeof(*sclient));
    if( uv_tls_init(server->loop, (evt_ctx_t*)server->data, sclient) < 0 ) {
        free(sclient);
        return;
    }
    r = uv_accept(server, (uv_stream_t*)&(sclient->skt));
    if(!r) {
        uv_tls_accept(sclient, on_uv_handshake);
    }
}

int uv_tls_writer(evt_tls_t *t, void *bfr, int sz)
{
    uv_buf_t b;
    b.base = bfr;
    b.len = sz;
    return uv_try_write(t->data, &b, 1);
}

int main()
{
    uv_loop_t *loop = uv_default_loop();
    int port = 8000;
    evt_ctx_t ctx;
    struct sockaddr_in bind_addr;
    int r = 0;

    evt_ctx_init_ex(&ctx, "server-cert.pem", "server-key.pem");
    evt_ctx_set_nio(&ctx, NULL, uv_tls_writer);

    uv_tcp_t listener;
    uv_tcp_init(loop, &listener);
    listener.data = &ctx;

    assert(0 == uv_ip4_addr("0.0.0.0", port, &bind_addr));

    r = uv_tcp_bind(&listener, (struct sockaddr*)&bind_addr, 0);
    if( r ) {
        fprintf( stderr, "bind: %s\n", uv_strerror(r));
    }

    r = uv_listen((uv_stream_t*)&listener, 128, on_connect_cb);
    if( r ) {
        fprintf( stderr, "listen: %s\n", uv_strerror(r));
    }
    printf("Listening on %d\n", port);

    uv_run(loop, UV_RUN_DEFAULT);

    evt_ctx_free(&ctx);
    return 0;
}
