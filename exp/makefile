
all: evt

evt:
	#$(CC) -g -Wall -I./ -Imbedtls/include evt.c
	$(CC) -g -Wall  evt_openssl.c -lcrypto -lpthread -lssl -lrt
