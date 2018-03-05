#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

#include "evt_mbed.h"

int main()
{
    evt_config_t *cfg = NULL;

    cfg = evt_default_cfg();
    assert(cfg != NULL && "test failed");
//    assert( cfg == evt_default && "test failed");
    assert( 1 == cfg->use_count && "test failed");
    assert( (cfg->verify_peer == EVT_VERIFY_REQUIRED) && "test failed");
    assert( (cfg->transport == EVT_IS_TLS) && "test failed");
    assert( (cfg->protocols == EVT_TLS_DEFAULT_PROTOCOL) && "test failed");
    assert( (strcasecmp(cfg->ciphers, "TLS1.2") == 0) && "test failed");

    cfg = evt_cfg_new();
    assert(cfg != NULL && "test failed");
//    assert( cfg != evt_default && "test failed");
    assert( 1 == cfg->use_count && "test failed");
    assert( (cfg->verify_peer == EVT_VERIFY_REQUIRED) && "test failed");
    assert( (cfg->transport == EVT_IS_TLS) && "test failed");
    assert( (cfg->protocols == EVT_TLS_DEFAULT_PROTOCOL) && "test failed");
    assert( (strcasecmp(cfg->ciphers, "TLS1.2") == 0) && "test failed");

    evt_cfg_del(cfg);

    //test the same thing after calling evt_init()
    assert( evt_init() == 0 && "test failed");

    cfg = evt_default_cfg();
    assert(cfg != NULL && "test failed");
  //  assert( cfg == evt_default && "test failed");
    assert( 1 == cfg->use_count && "test failed");
    assert( (cfg->verify_peer == EVT_VERIFY_REQUIRED) && "test failed");
    assert( (cfg->transport == EVT_IS_TLS) && "test failed");
    assert( (cfg->protocols == EVT_TLS_DEFAULT_PROTOCOL) && "test failed");
    assert( (strcasecmp(cfg->ciphers, "TLS1.2") == 0) && "test failed");

    cfg = evt_cfg_new();
    assert(cfg != NULL && "test failed");
   // assert( cfg != evt_default && "test failed");
    assert( 1 == cfg->use_count && "test failed");
    assert( (cfg->verify_peer == EVT_VERIFY_REQUIRED) && "test failed");
    assert( (cfg->transport == EVT_IS_TLS) && "test failed");
    assert( (cfg->protocols == EVT_TLS_DEFAULT_PROTOCOL) && "test failed");
    assert( (strcasecmp(cfg->ciphers, "TLS1.2") == 0) && "test failed");

    evt_cfg_del(cfg);

    printf("Test passed\n");
}
