all: clean evt gen_cert test_uv_tls
evt:
	clang -g -Wall -o $@ new.c evt_tls.c -lssl -lcrypto -lrt

gen_cert:
	openssl req -x509 -newkey rsa:2048 -nodes -keyout server-key.pem  \
        -out server-cert.pem -config ssl_test.cnf

test_uv_tls:
	clang -g -Wall -o $@ test_tls.c uv_tls.c evt_tls.c -lssl -lcrypto -lrt

       

clean:
	-rm evt
