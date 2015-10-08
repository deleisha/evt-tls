#include <assert.h>
#include "uv_tls.h"

void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    buf->base = (char*)malloc(size);
    memset(buf->base, 0, size);
    buf->len = size;
    assert(buf->base != NULL && "Memory allocation failed");
}

void on_uv_close(uv_handle_t *hdl)
{
    free(hdl);
}

void on_close(evt_tls_t *t, int status)
{
    uv_tls_t *ut = (uv_tls_t*)t->data;
    evt_tls_delete(t);
    uv_close( (uv_handle_t*)&(ut->skt), on_uv_close);
}

int uv_tls_close(uv_tls_t *strm, evt_close_cb cb)
{
    return evt_tls_close(strm->tls, cb);
}

void on_tcp_read(uv_stream_t *stream, ssize_t nrd, const uv_buf_t *data)
{
    uv_tls_t *parent = CONTAINER_OF(stream, uv_tls_t, skt);
    assert( parent != NULL);
    if ( nrd <= 0 ) {
        if( nrd == UV_EOF) {
            uv_tls_close(parent, on_close);
        }
        free(data->base);
        return;
    }
    evt_tls_feed_data(parent->tls, data->base, nrd);
    free(data->base);
}

void on_write(evt_tls_t *tls, int status)
{
    uv_tls_close((uv_tls_t*)tls->data, on_close);
}

int uv_tls_write(uv_tls_t *stream, uv_buf_t *buf, evt_write_cb cb)
{
    return evt_tls_write(stream->tls, buf->base, buf->len, cb);
}

void evt_on_rd(evt_tls_t *t, char *bfr, int sz)
{
    uv_buf_t data;
    data.base = bfr;
    data.len = sz;

    uv_tls_write((uv_tls_t*)t->data, &data, on_write);
}


int uv_tls_read(uv_tls_t *t, uv_alloc_cb alloc_cb, evt_read_cb cb)
{
    return evt_tls_read(t->tls, cb);
}

void on_hd_complete( evt_tls_t *t, int status)
{
    uv_tls_t *ut = (uv_tls_t*)t->data;
    if ( 1 == status ) {
        uv_tls_read(ut, alloc_cb, evt_on_rd);
    }
    else {
        uv_tls_close(ut, on_close);
    }
}

int uv_tls_accept(uv_tls_t *t, evt_accept_cb cb)
{
    evt_tls_t *tls = t->tls;
    evt_tls_set_role(tls, 1);
    tls->accept_cb = cb;
    return uv_read_start((uv_stream_t*)&(t->skt), alloc_cb, on_tcp_read);
}


void on_connect_cb(uv_stream_t *server, int status)
{
    if( status ) {
        return;
    }
    //memory being freed at on_close
    uv_tls_t *sclient = malloc(sizeof(*sclient));
    if( uv_tls_init(server->loop, (evt_ctx_t*)server->data, sclient) < 0 ) {
        fprintf( stderr, "TLS setup error\n");
        free(sclient);
        return;
    }

    int r = uv_accept(server, (uv_stream_t*)&(sclient->skt));
    if(!r) {
        uv_tls_accept(sclient, on_hd_complete);
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
    uv_loop_t *loop;
    evt_ctx_t ctx;
    const int port = 8000;
    struct sockaddr_in bind_addr;
    int r = 0;

    loop = uv_default_loop();

    evt_ctx_init(&ctx);
    evt_ctx_set_crt_key(&ctx, "server-cert.pem", "server-key.pem");
    evt_ctx_set_writer(&ctx, uv_tls_writer);

    uv_tcp_t listener;
    uv_tcp_init(loop, &listener);
    listener.data = &ctx;

    r = uv_ip4_addr("0.0.0.0", port, &bind_addr);
    assert(0 == r);
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
