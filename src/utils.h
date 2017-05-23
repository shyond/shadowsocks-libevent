#ifndef _UTILS_H
#define _UTILS_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <time.h>



extern FILE *logfile;
#define	TIME_FORMAT  "%Y-%m-%d %H:%M:%S"

#define  USE_LOGFILE(ident)										\
	do{															\
		if(ident != NULL){logfile = fopen(ident,"w+");}			\
	}while(0)                          

#define	CLOSE_LOGFILE()											\
	do{															\
		if(logfile != NULL){fclose(logfile);logfile = NULL;}	\
	}while(0)


#define LOGI(format, ...)										\
	do{															\
		if(logfile != NULL){									\
			time_t now = time(0);								\
			char timestr[20];									\
			strftime(timestr,20,TIME_FORMAT,localtime(&now));	\
			fprintf(logfile," %s INFO: " format "\n",timestr,	\
					## __VA_ARGS__);							\
			fflush(logfile);}									\
	}while(0)

#define LOGE(format, ...)										\
	do{															\
		if(logfile != NULL){									\
			time_t now = time(0);								\
			char timestr[20];									\
			strftime(timestr,20,TIME_FORMAT,localtime(&now));	\
			fprintf(logfile," %s ERROR: " format "\n",timestr,	\
					## __VA_ARGS__);							\
			fflush(logfile);}									\
	}while(0)


void FATAL(const char *msg);

void usage();
void *ss_malloc(size_t size);
void *ss_realloc(void *ptr, size_t new_size);

#define  ss_free(ptr)    \
	do{                  \
           free(ptr);    \
	       ptr = NULL;   \
	 }while(0)     



#endif
