#ifndef _PROTOCOL_H
#define _PROTOCOL_H

typedef struct protocol {
	const int default_port;
	int(*const parse_packet)(const char *, size_t, char **);
} protocol_t;


#endif