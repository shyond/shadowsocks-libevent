#include "utils.h"

FILE *logfile;

void usage()
{

}


void *ss_malloc(size_t size)
{
	void *tmp = malloc(size);
	if(!tmp)
		return NULL;
	return tmp;
}

void *ss_realloc(void *ptr, size_t new_size)
{
	void *tmp = realloc(ptr, new_size);
	if (tmp == NULL) {
		free(ptr);
		ptr = NULL;
		exit(EXIT_FAILURE);
	}
	return tmp;
}

void FATAL(const char *msg)
{
	LOGE("%s", msg);
	exit(-1);
}