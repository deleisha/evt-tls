ROOT = ../../
LIB_2_LINK =                    \
  -lssl                         \
  -lcrypto                      \
  -lrt                          \
  libuv/out/Debug/libuv.a       \
  -ldl                          \
  -lpthread                     \

all:evt client

evt:
	cd libuv && python gyp_uv.py
	make -C ./libuv/out
	$(CC) -g -Wall -o $@ -I$(ROOT) -I$(ROOT)/api test_tls.c $(ROOT)/src/evt_tls.c uv_tls.c $(LIB_2_LINK)

client:
	cd libuv && python gyp_uv.py
	make -C ./libuv/out
	$(CC) -g -Wall -o $@ -I$(ROOT) -I $(ROOT)/api tls_client_test.c $(ROOT)/src/evt_tls.c uv_tls.c $(LIB_2_LINK)

        
clean:
	-rm -fv evt
	-rm -fv client
