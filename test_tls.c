#include <assert.h>
#include "uv_tls.h"

void on_connect_cb(uv_stream_t *strm, int status)
{
    if ( status ) {
        return;
    }
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

    uv_tcp_t listener;

    uv_tcp_init(loop, &listener);

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
    return 0;
}
