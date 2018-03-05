#include <mbedtls/ssl.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"


typedef struct evt_config_s
{
    //all const chars are dynamically managed
    const char *ca_store;
    const char *ca_file;
    const char *crl_path;
    const char *cert_file;
    const char *key_file;
    const char *ciphers;

    int         cfg_err;
    uint32_t    protocols;
    uint32_t    transport; /* TCP or UDP - Default is TCP */
    uint32_t    verify_peer;
    int         ca_depth;
    int         use_count;
}evt_config_t;


typedef enum evt_endpt_t {
    ENDPT_IS_UNSPECIFIED
   ,ENDPT_IS_CLIENT
   ,ENDPT_IS_SERVER
}evt_endpt_t;


typedef struct evt_tls_s evt_tls_t;
typedef void (*evt_handshake_cb)( evt_tls_t *conn, int status);
typedef const char* (*evt_cacert_cb)(evt_tls_t *);
/* generate this through macro when dtls need to be supported */
struct evt_tls_s {
    int                            tls_err;
    evt_endpt_t                    role;
    uint32_t                       state;

    void                           *user_data;

    evt_config_t                   *config;

    evt_handshake_cb               handshake_cb;
    evt_cacert_cb                  get_ca_cert;


    mbedtls_entropy_context        entropy;
    mbedtls_ctr_drbg_context       ctr_drbg;
    mbedtls_ssl_context            ssl_conn;
    mbedtls_ssl_config             mconf;
    mbedtls_x509_crt               cert;
    mbedtls_x509_crt               ca_certs;
    mbedtls_pk_context             pkey;
};

typedef enum evt_error_t {
    EVT_ERR_NONE = 0

   ,EVT_ERR_NOMEM

   ,EVT_ERR_NO_KEYPAIR
   ,EVT_ERR_CIPHER_FAIL

   ,EVT_ERR_NOROLE
   ,EVT_ERR_HSHAKE_DONE
   ,EVT_ERR_NOCFG
   ,EVT_ERR_BADCERT
   ,EVT_ERR_HSHAKE
   ,EVT_ERR_ESEED

   ,EVT_ERR_MAX_COUNT /* Don't add any entry after this line */
} evt_error_t;

static const char *err_str[] = {
    "No error found"
   ,"Insufficient memory"
   ,"Cert or Key or Both required"
   ,"Cipher setting failed"
   ,"No role specified"
   ,"Handshake completed already"
   ,"Not configured yet"
   ,"Bad cert detected"
   ,"Handshake failed at underlying library"
   ,"Seeding failed"
};


#define EVT_TLS_1_0                 (1 << 0)
#define EVT_TLS_1_1                 (1 << 1)
#define EVT_TLS_1_2                 (1 << 2)

#define EVT_PROTOCOLS_TLS_1         (EVT_TLS_1_0|EVT_TLS_1_1|EVT_TLS_1_2)

#define EVT_TLS_PROTOCOL_ALL        EVT_PROTOCOLS_TLS_1
#define EVT_TLS_DEFAULT_PROTOCOL    EVT_TLS_1_2
#define EVT_DEFAULT_CIPHERS   "TLSv1.2"





#define EVT_IS_TLS    1
#define EVT_IS_DTLS   2


#define EVT_NEED_FLUSH                              (-2)
#define EVT_NEED_READ                               (-3)

#define EVT_HANDSHAKE_COMPLETED                     (1 << 3)



#define EVT_VERIFY_NONE             0
#define EVT_VERIFY_OPTIONAL         1
#define EVT_VERIFY_REQUIRED         2


evt_config_t*
evt_default_cfg(void);

evt_config_t*
evt_cfg_new(void);

int
evt_init(void);





evt_error_t
evt_tls_get_err(const evt_tls_t *tls);

void
evt_tls_set_err( evt_tls_t *tls, evt_error_t err);

evt_tls_t *evt_tls_new(void);
void evt_tls_free(evt_tls_t *tls);

evt_tls_t *evt_tls_client(void);
evt_tls_t *evt_tls_server(void);


int evt_configure( evt_tls_t *tls, evt_config_t *cfg);
int evt_tls_is_handshake_done(const evt_tls_t *conn);

int evt_tls_handshake(evt_tls_t *conn, evt_handshake_cb hcb);

int evt_tls_connect(evt_tls_t *conn, evt_handshake_cb hcb);
int evt_tls_accept(evt_tls_t *conn, evt_handshake_cb hcb);
    
evt_error_t
evt_cfg_get_err(const evt_config_t *cfg);

void
evt_cfg_set_err(evt_config_t *cfg, evt_error_t code);

const char *evt_cfg_strerror(const evt_config_t *cfg);
int
evt_cfg_set_crtf_key(evt_config_t *cfg, const char *cert, const char *key);

int evt_cfg_set_ca_path( evt_config_t *cfg, char *ca_path);

int evt_cfg_set_crl_path( evt_config_t *cfg, char *crl_path);
int evt_cfg_set_ciphers(evt_config_t *cfg, char *ciphers);
void evt_cfg_set_protocols(evt_config_t *cfg, int proto);
void evt_cfg_set_transport(evt_config_t *cfg, int transport);
void evt_cfg_set_verify(evt_config_t *cfg, int mode);
void evt_cfg_del( evt_config_t *cfg);
