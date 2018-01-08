/**
 * \brief          Callback type: send data on the network.
 *
 * \note           That callback may be either blocking or non-blocking.
 *
 * \param ctx      Context for the send callback (typically a file descriptor)
 * \param buf      Buffer holding the data to send
 * \param len      Length of the data to send
 *
 * \return         The callback must return the number of bytes sent if any,
 *                 or a non-zero error code.
 *                 If performing non-blocking I/O, \c MBEDTLS_ERR_SSL_WANT_WRITE
 *                 must be returned when the operation would block.
 *
 * \note           The callback is allowed to send fewer bytes than requested.
 *                 It must always return the number of bytes actually sent.
 */
typedef int mbedtls_ssl_send_t( void *ctx,
                                const unsigned char *buf,
                                size_t len );

/**
 * \brief          Callback type: receive data from the network.
 *
 * \note           That callback may be either blocking or non-blocking.
 *
 * \param ctx      Context for the receive callback (typically a file
 *                 descriptor)
 * \param buf      Buffer to write the received data to
 * \param len      Length of the receive buffer
 *
 * \return         The callback must return the number of bytes received,
 *                 or a non-zero error code.
 *                 If performing non-blocking I/O, \c MBEDTLS_ERR_SSL_WANT_READ
 *                 must be returned when the operation would block.
 *
 * \note           The callback may receive fewer bytes than the length of the
 *                 buffer. It must always return the number of bytes actually
 *                 received and written to the buffer.
 */
typedef int mbedtls_ssl_recv_t( void *ctx,
                                unsigned char *buf,
                                size_t len );





#include <uv.h>

void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *bfr)
{
}


int my_recv(void *, unsigned char *buf, size_t len)
{

    buf = 
    len = nread;
    uv_read_start(uv_stream_t*,
                            uv_alloc_cb alloc_cb,
                            uv_read_cb read_cb);


}


int my_net_sent(void *ctx, const unsigned char *buf, size_t len)
{
    uv_write(uv_write_t* req, uv_stream_t* handle, const uv_buf_t bufs[],
                       unsigned int nbufs,
                       uv_write_cb cb);

}

int main()
{

}
