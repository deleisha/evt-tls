#include <stdio.h>
#include <assert.h>

#include "evt_mbed.h"

void on_handshake(evt_tls_t *tls, int status)
{
    fprintf(stderr, "on handshake called\n");
}


int main()
{
    evt_config_t *cfg = evt_cfg_new();
    evt_tls_t *client = evt_tls_client();
    assert( client != NULL  && "Test failed");
    assert( client->role == ENDPT_IS_CLIENT && "Test failed");
    if ( evt_configure( client, cfg) != 0 ) {
        goto err;
    }

    evt_tls_t *server = evt_tls_server();
    assert( server != NULL && "Test failed");
    assert( server->role == ENDPT_IS_SERVER && "Test failed");

    if ( evt_configure( server, cfg) != 0 ) {
        goto err;
    }

    if ( evt_tls_handshake(client, on_handshake) != 0 )
    {
        goto err;
    }

    if (evt_tls_handshake(server, on_handshake) != 0 ) {
        goto err;
    }

    fprintf(stdout, "Test passed\n");
    return 0;

err:
    fprintf(stderr, "Test failed\n");
}
