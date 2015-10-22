all: clean evt test_evt gen_cert test
evt:
	make -C sample/libuv-tls evt

gen_cert:
	openssl req -x509 -newkey rsa:2048 -nodes -keyout server-key.pem  \
        -out server-cert.pem -config ssl_test.cnf

test_evt:
	clang -g -Wall -o $@ evt_test.c evt_tls.c -lssl -lcrypto -lrt

test:
	./test_evt

clean:
	make -C sample/libuv-tls clean
	-rm test_evt
