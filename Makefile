all: clean test_evt gen_cert test

#This target needs libuv to be built, check www.libuv.org for building it
evt:
	make -C sample/libuv-tls evt

gen_cert:
	openssl req -x509 -newkey rsa:2048 -nodes -keyout server-key.pem  \
        -out server-cert.pem -config ssl_test.cnf
	-cp -rf server-cert.pem server-key.pem sample/libuv-tls/

test_evt:
	$(CC) -g -Wall -o $@ -Iapi -I./ evt_test.c src/evt_tls.c -lssl -lcrypto -lrt

test:
	./test_evt

clean:
	make -C sample/libuv-tls clean
	-rm test_evt
