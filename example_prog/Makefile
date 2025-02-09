all: libhello.so test test_threaded

libhello.so: libhello.c
	gcc libhello.c -fPIC -shared -o libhello.so

test: test.c
	gcc test.c -o test

test_threaded: test_threaded.c
	gcc test_threaded.c -o test_threaded -lpthread
