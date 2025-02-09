#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>

#define NUM_THREADS 8

void *worker(void *ptr)
{
	pid_t pid = getpid();
	pid_t tid = gettid();
	printf("hello from worker thread. pid=%u, tid=%u\n", pid, tid);
	while (1) {
		sleep(NUM_THREADS);
		printf("still running... pid=%u, tid=%u\n", pid, tid);
	}
}

int main()
{
	pthread_t threads[NUM_THREADS];
	printf("test_threaded.c started with pid=%u\n", getpid());
	for (int i=0; i<NUM_THREADS; i++) {
		sleep(1);
		pthread_create(&threads[i], NULL, *worker, NULL);
	}
	while (1) {
		sleep(1);
		printf("test_threaded.c main thread is still running...\n");
	}
}
