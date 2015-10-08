all: clean evt new gen_cert
evt:
	cd libuv && python gyp_uv.py
	make -C ./libuv/out
	clang -g -Wall -o $@ test_tls.c evt_tls.c uv_tls.c -lssl -lcrypto -lrt libuv/out/Debug/libuv.a -ldl -lpthread

gen_cert:
	openssl req -x509 -newkey rsa:2048 -nodes -keyout server-key.pem  \
        -out server-cert.pem -config ssl_test.cnf

new:
	clang -g -Wall -o $@ new.c evt_tls.c -lssl -lcrypto -lrt

       

clean:
	-rm evt
	-rm new
