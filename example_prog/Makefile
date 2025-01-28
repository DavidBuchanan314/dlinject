all: libhello.so test

libhello.so: libhello.c
	gcc libhello.c -fPIC -shared -o libhello.so

test: test.c
	gcc test.c -o test
