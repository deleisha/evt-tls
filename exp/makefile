
all: evt

evt: mbed mtls
	#$(CC) -g -Wall -I./ -Imbedtls/include evt.c
	$(CC) -o $@ -g -Wall  evt_openssl.c -lcrypto -lpthread -lssl -lrt

mbed:
	$(CC) -o $@ -g evt_mbed.c test_evt_cfg.c -I../mbedtls/include    \
	    -L ../mbedtls/library -lmbedtls -lmbedx509 -lmbedcrypto

mtls:
	$(CC) -o $@ -g evt_mbed.c test_evt_tls.c -I../mbedtls/include   \
	    -L ../mbedtls/library -lmbedtls -lmbedx509 -lmbedcrypto



clean:
	-rm evt
	-rm mbed
	-rm mtls
