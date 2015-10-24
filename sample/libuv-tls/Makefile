ROOT = ../../
LIB_2_LINK =                    \
  -lssl                         \
  -lcrypto                      \
  -lrt                          \
  libuv/out/Debug/libuv.a       \
  -ldl                          \
  -lpthread                     \

evt:
	cd libuv && python gyp_uv.py
	make -C ./libuv/out
	$(CC) -g -Wall -o $@ -I $(ROOT)/ test_tls.c $(ROOT)/evt_tls.c uv_tls.c $(LIB_2_LINK)
        
clean:
	-rm -fv evt
	-rm -fv server-cert.pem server-key.pem
