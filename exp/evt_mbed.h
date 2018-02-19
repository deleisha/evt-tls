#ifndef EVT_MBEDTLS_H
#define EVT_MBEDTLS_H

#include <mbedtls/ssl.h>



#define TLS_CIPHERS_DEFAULT	"TLSv1.2+AEAD+ECDHE:TLSv1.2+AEAD+DHE"
#define TLS_CIPHERS_COMPAT	"HIGH:!aNULL"
#define TLS_CIPHERS_LEGACY	"HIGH:MEDIUM:!aNULL"
#define TLS_CIPHERS_ALL		"ALL:!aNULL:!eNULL"

#define TLS_ECDHE_CURVES	"X25519,P-256,P-384"

struct tls_error {
	char *msg;
	int num;
	int tls;
};

struct tls_keypair {
	struct tls_keypair *next;

	char *cert_mem;
	size_t cert_len;
	char *key_mem;
	size_t key_len;
	char *pubkey_hash;
};



#define TLS_NUM_TICKETS				4
#define TLS_TICKET_NAME_SIZE			16
#define TLS_TICKET_AES_SIZE			32
#define TLS_TICKET_HMAC_SIZE			16

struct tls_config {
	struct tls_error error;

	int refcount;

	const char *ca_path;
	char *ca_mem;
	size_t ca_len;
	const char *ciphers;
	int ciphers_server;
	struct tls_keypair *keypair;
	uint32_t protocols;
	int verify_cert;
	int verify_client;
	int verify_depth;
	int verify_name;
	int verify_time;
	int skip_private_key_check;
};

struct tls_conninfo {
	char *cipher;
	char *servername;
	char *version;

	char *hash;
	char *issuer;
	char *subject;

	uint8_t *peer_cert;
	size_t peer_cert_len;

	time_t notbefore;
	time_t notafter;
};

#define TLS_CLIENT		(1 << 0)
#define TLS_SERVER		(1 << 1)
#define TLS_SERVER_CONN		(1 << 2)

#define TLS_EOF_NO_CLOSE_NOTIFY	(1 << 0)
#define TLS_CONNECTED		(1 << 1)
#define TLS_HANDSHAKE_COMPLETE	(1 << 2)
#define TLS_SSL_NEEDS_SHUTDOWN	(1 << 3)

};


struct tls {
	struct tls_config *config;
	struct tls_keypair *keypair;

	struct tls_error error;

	uint32_t flags;
	uint32_t state;

	char *servername;
	int socket;

	SSL *ssl_conn;
	SSL_CTX *ssl_ctx;

	struct tls_sni_ctx *sni_ctx;

	X509 *ssl_peer_cert;
	STACK_OF(X509) *ssl_peer_chain;

	struct tls_conninfo *conninfo;

	struct tls_ocsp *ocsp;

	tls_read_cb read_cb;
	tls_write_cb write_cb;
	void *cb_arg;
};

int tls_set_mem(char **_dest, size_t *_destlen, const void *_src,
    size_t _srclen);
int tls_set_string(const char **_dest, const char *_src);

struct tls_keypair *tls_keypair_new(void);
void tls_keypair_clear(struct tls_keypair *_keypair);
void tls_keypair_free(struct tls_keypair *_keypair);
int tls_keypair_set_cert_file(struct tls_keypair *_keypair,
    struct tls_error *_error, const char *_cert_file);
int tls_keypair_set_cert_mem(struct tls_keypair *_keypair,
    struct tls_error *_error, const uint8_t *_cert, size_t _len);
int tls_keypair_set_key_file(struct tls_keypair *_keypair,
    struct tls_error *_error, const char *_key_file);
int tls_keypair_set_key_mem(struct tls_keypair *_keypair,
    struct tls_error *_error, const uint8_t *_key, size_t _len);
int tls_keypair_set_ocsp_staple_file(struct tls_keypair *_keypair,
    struct tls_error *_error, const char *_ocsp_file);
int tls_keypair_set_ocsp_staple_mem(struct tls_keypair *_keypair,
    struct tls_error *_error, const uint8_t *_staple, size_t _len);
int tls_keypair_load_cert(struct tls_keypair *_keypair,
    struct tls_error *_error, X509 **_cert);

struct tls_sni_ctx *tls_sni_ctx_new(void);
void tls_sni_ctx_free(struct tls_sni_ctx *sni_ctx);

struct tls *tls_new(void);
struct tls *tls_server_conn(struct tls *ctx);

int tls_check_name(struct tls *ctx, X509 *cert, const char *servername,
    int *match);
int tls_configure_server(struct tls *ctx);

int tls_configure_ssl(struct tls *ctx, SSL_CTX *ssl_ctx);
int tls_configure_ssl_keypair(struct tls *ctx, SSL_CTX *ssl_ctx,
    struct tls_keypair *keypair, int required);
int tls_configure_ssl_verify(struct tls *ctx, SSL_CTX *ssl_ctx, int verify);

int tls_handshake_client(struct tls *ctx);
int tls_handshake_server(struct tls *ctx);

int tls_config_load_file(struct tls_error *error, const char *filetype,
    const char *filename, char **buf, size_t *len);
int tls_config_ticket_autorekey(struct tls_config *config);
int tls_host_port(const char *hostport, char **host, char **port);

int tls_set_cbs(struct tls *ctx,
    tls_read_cb read_cb, tls_write_cb write_cb, void *cb_arg);

void tls_error_clear(struct tls_error *error);
int tls_error_set(struct tls_error *error, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)))
    __attribute__((__nonnull__ (2)));
int tls_error_setx(struct tls_error *error, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)))
    __attribute__((__nonnull__ (2)));
int tls_config_set_error(struct tls_config *cfg, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)))
    __attribute__((__nonnull__ (2)));
int tls_config_set_errorx(struct tls_config *cfg, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)))
    __attribute__((__nonnull__ (2)));
int tls_set_error(struct tls *ctx, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)))
    __attribute__((__nonnull__ (2)));
int tls_set_errorx(struct tls *ctx, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)))
    __attribute__((__nonnull__ (2)));
int tls_set_ssl_errorx(struct tls *ctx, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)))
    __attribute__((__nonnull__ (2)));

int tls_ssl_error(struct tls *ctx, SSL *ssl_conn, int ssl_ret,
    const char *prefix);

int tls_conninfo_populate(struct tls *ctx);
void tls_conninfo_free(struct tls_conninfo *conninfo);

int tls_ocsp_verify_cb(SSL *ssl, void *arg);
int tls_ocsp_stapling_cb(SSL *ssl, void *arg);
void tls_ocsp_free(struct tls_ocsp *ctx);
struct tls_ocsp *tls_ocsp_setup_from_peer(struct tls *ctx);
int tls_hex_string(const unsigned char *_in, size_t _inlen, char **_out,
    size_t *_outlen);
int tls_cert_hash(X509 *_cert, char **_hash);
int tls_cert_pubkey_hash(X509 *_cert, char **_hash);

int tls_password_cb(char *_buf, int _size, int _rwflag, void *_u);

__END_HIDDEN_DECLS

/* XXX this function is not fully hidden so relayd can use it */
void tls_config_skip_private_key_check(struct tls_config *config);

#endif
