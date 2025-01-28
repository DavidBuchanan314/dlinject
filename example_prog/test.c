#include <stdio.h>
#include <unistd.h>

int main()
{
	printf("test.c started with pid=%u\n", getpid());
	while (1) {
		sleep(1);
		printf("test.c is still running...\n");
	}
}
