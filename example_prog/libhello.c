#include <stdio.h>
#include <unistd.h>

__attribute__ ((constructor))
void init()
{
	fprintf(stderr, "\nHello, world! I've been injected into pid %u\n", getpid());
}
