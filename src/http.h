#ifndef _HTTP_H
#define _HTTP_H


typedef struct protocol {
	const int default_port;
	int(*const parse_packet)(const char *, size_t, char **);
} protocol_t;

const protocol_t *const http_protocol;

#endif