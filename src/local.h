#ifndef  _LOCAL_H
#define  _LOCAL_H

#include <event.h>
#include "local.h"

typedef struct listen_ctx{

	event_base* base;
	bufferevent* bevent;
	int fd;
	struct sockaddr** remote_addr;

}listen_ctx_t;

typedef struct server_ctx{
	event_base* base;
	bufferevent* bevent;
	int connected;
	struct server* server;
}server_ctx_t;

typedef struct server{
	int fd;
	char stage;
	struct enc_ctx *e_ctx;
	struct enc_ctx *d_ctx;
	struct server_ctx *recv_ctx;
	struct server_ctx *send_ctx;
	struct listen_ctx *listener;
	struct remote *remote;

}server_t;

typedef struct remote_ctx {
	event_base* base;
	bufferevent* bevent;
	struct remote *remote;
} remote_ctx_t;

typedef struct remote {
	int fd;
	buffer_t *buf;
	int direct;
	struct remote_ctx *recv_ctx;
	struct remote_ctx *send_ctx;
	struct server *server;
	
} remote_t;
#endif