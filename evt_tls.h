#ifndef EVT_TLS_H
#define EVT_TLS_H


#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include "queue.h"


typedef struct evt_tls_s evt_tls_t;

typedef void (*evt_conn_cb)(evt_tls_t *con, int status);
typedef void (*evt_accept_cb)(evt_tls_t *con, int status);
typedef void (*evt_allocator)(evt_tls_t *con, int size, void *buf);
typedef void (*evt_read_cb)(evt_tls_t *con, void *buf, int size);
typedef void (*evt_write_cb)(evt_tls_t *con, int status);

typedef int (*net_wrtr)(evt_tls_t *tls, void *edata, int len);
typedef int (*net_rdr)(evt_tls_t *tls, void *edata, int len);


struct evt_tls_s {
    BIO     *app_bio_; //Our BIO, All IO should be through this

    SSL     *ssl;

    
    BIO     *ssl_bio_; //the ssl BIO used only by openSSL

    //network writer used for writing encrypted data
    net_wrtr writer;

    evt_conn_cb connect_cb;
    evt_accept_cb accept_cb;

    evt_allocator allocator;
    evt_read_cb rd_cb;
    evt_write_cb write_cb;

    QUEUE q;
};


typedef struct evt_ctx_s
{
    //find better place for it , should be one time init
    SSL_CTX *ctx;

    //flags which tells if cert is set
    int cert_set;

    //flags which tells if key is set
    int key_set;

    //flag to signify if ssl error has occured
    int ssl_err_;

    void *live_con[2];

    net_wrtr writer;
    net_rdr  rdr
} evt_ctx_t;


//supported TLS operation
enum tls_op_type {
    EVT_TLS_OP_HANDSHAKE
   ,EVT_TLS_OP_READ
   ,EVT_TLS_OP_WRITE
   ,EVT_TLS_OP_SHUTDOWN
};

/*configure the tls state machine */
int evt_ctx_init(evt_ctx_t *tls);

/* set the certifcate and key in order */
int evt_ctx_set_crt_key(evt_ctx_t *tls, char *crtf, char *key);

/* test if the certificate */
int evt_ctx_is_crtf_set(evt_ctx_t *t);

/* test if the key is set */
int evt_ctx_is_key_set(evt_ctx_t *t);

evt_tls_t *getSSL(evt_ctx_t *d_eng);
void evt_ctx_set_writer(evt_ctx_t *ctx, net_wrtr my_writer);

int evt_tls_feed_data(evt_tls_t *c, void *data, int sz);
int after__wrk(evt_tls_t *c, void *buf);
int evt__ssl_op(evt_tls_t *c, enum tls_op_type op, void *buf, int *sz);
void evt_tls_set_nio(evt_tls_t *c, int (*fn)(evt_tls_t *t, void *data, int sz));


int evt_tls_connect(evt_tls_t *con, evt_conn_cb cb);
int evt_tls_accept( evt_tls_t *tls, evt_accept_cb cb);
int evt_tls_write(evt_tls_t *c, void *msg, int *str_len, evt_write_cb on_write);
int evt_tls_read(evt_tls_t *c, evt_allocator allok, evt_read_cb on_read );


#ifdef __cplusplus 
}
#endif

#endif //define EVT_TLS_H
