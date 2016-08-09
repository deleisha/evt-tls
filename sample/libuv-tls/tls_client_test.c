#include "uv_tls.h"

void on_connect(uv_connect_t *req, int status)
{
    fprintf( stderr, "Entering tls_connect callback\n");
    if( status ) {
        fprintf( stderr, "TCP connection error\n");
        return;
    }
    fprintf( stderr, "TCP connection established\n");

    evt_ctx_t *ctx = req->handle->data;

//    uv_tls_t *clnt = req->handle->data;
//    uv_write_t *rq = (uv_write_t*)malloc(sizeof(*rq));
//    uv_buf_t dcrypted;
//    dcrypted.base = "Hello from lib-tls";
//    dcrypted.len = strlen(dcrypted.base);
//    assert(rq != 0);
//    uv_tls_write(rq, clnt, &dcrypted, on_write);
}


int main()
{
    uv_loop_t *loop = uv_default_loop();
    uv_tcp_t client;
    uv_tcp_init(loop, &client);
    int port = 8000;
 
    evt_ctx_t ctx;
    evt_ctx_init_ex(&ctx, "server-cert.pem", "server-key.pem");
    evt_ctx_set_nio(&ctx, NULL, uv_tls_writer);


    struct sockaddr_in conn_addr;
    int r = uv_ip4_addr("127.0.0.1", port, &conn_addr);

    uv_connect_t req;
    req.data = &ctx;
    uv_tcp_connect(&req, &client, (const struct sockaddr*)&conn_addr, on_connect);

    uv_run(loop, UV_RUN_DEFAULT);

    return 0;
}
