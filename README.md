# evt-tls
evt-tls is an abstraction layer of OpenSSL using bio pair to expose callback based asynchronous API and should integrate easily with any event based networking library like libuv, libevent and libev or any other network library which want to
use OpenSSL as an state machine.

The evt-tls will evaluate and try to support other TLS library like libtls, mbedtls etc.

The work is in alpha stage and lot of work is still going on to make production ready. 

`Until then, Keep Watching for More Actions on This Space`

# How the evt-tls work
evt-tls uses the BIO-pair from OpenSSL, which is the suggested way, for using TLS engine for handling network I/O(nio) independently. Hence, user is responsible for nio and feed TLS engine with whatever data we receive from network. Evt will unwrap the data and give you application data via a callback. It also wraps data and write to network.

# How to work with evt-tls
Sample integrations and usage can be found in `sample/libuv-tls` for integration with libuv. `Integrations with other libraries are most welcome for contributions`. Sample usage can also be seen at `evt_test.c`. These are the sources of
tutorials until a better document comes. `If anybody want to contribute doc, Most welcome.`
```C

#include "uv_tls.h"

void on_write(uv_tls_t *tls, int status) {
    uv_tls_close(tls, (uv_tls_close_cb)free);
}

void uv_rd_cb( uv_tls_t *strm, ssize_t nrd, const uv_buf_t *bfr) {
    if ( nrd <= 0 ) return;
    uv_tls_write(strm, (uv_buf_t*)bfr, on_write);
}

void on_uv_handshake(uv_tls_t *ut, int status) {
    if ( 0 == status )
        uv_tls_read(ut, uv_rd_cb);
    else
        uv_tls_close(ut, (uv_tls_close_cb)free);
}

void on_connect_cb(uv_stream_t *server, int status) {
    if( status ) return;
    uv_tcp_t *tcp = malloc(sizeof(*tcp)); //freed on uv_close callback
    uv_tcp_init(uv_default_loop(), tcp);
    if (uv_accept(server, (uv_stream_t*)tcp)) {
        return;
    }

    uv_tls_t *sclient = malloc(sizeof(*sclient)); //freed on uv_close callback
    if( uv_tls_init((evt_ctx_t*)server->data, tcp, sclient) < 0 ) {
        free(sclient);
        return;
    }
    uv_tls_accept(sclient, on_uv_handshake);
}

int main() {
    uv_loop_t *loop = uv_default_loop();
    int port = 8000, r = 0;
    evt_ctx_t ctx;
    struct sockaddr_in bind_local;

    evt_ctx_init_ex(&ctx, "server-cert.pem", "server-key.pem");
    evt_ctx_set_nio(&ctx, NULL, uv_tls_writer);

    uv_tcp_t listener_local;
    uv_tcp_init(loop, &listener_local);
    listener_local.data = &ctx;
    uv_ip4_addr("127.0.0.1", port, &bind_local);
    if ((r = uv_tcp_bind(&listener_local, (struct sockaddr*)&bind_local, 0)))
        fprintf( stderr, "bind: %s\n", uv_strerror(r));

    if ((r = uv_listen((uv_stream_t*)&listener_local, 128, on_connect_cb)))
        fprintf( stderr, "listen: %s\n", uv_strerror(r));
    printf("Listening on %d\n", port);
    uv_run(loop, UV_RUN_DEFAULT);
    evt_ctx_free(&ctx);
    return 0;
}

```
# BUILD AND TEST
To join the actions, download the code and to build and test

`make`
