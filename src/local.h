#ifndef  _LOCAL_H
#define  _LOCAL_H

#include <event2/event.h>
#include <event2/bufferevent.h>
#include "local.h"
#include "encrypt.h"


typedef struct listen_ctx{
	event_base *base;
	int fd;
	int remote_num;
	int method;
	struct sockaddr **remote_addrs;
	int timeout;//连接超时
}listen_ctx_t;

typedef struct server_ctx{
	int connected;
	struct server *server;
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
	buffer_t *buf;
	event_base *base;
	bufferevent *bevent;
}server_t;

typedef struct remote_ctx {
    int connected;
	struct remote *remote;
	event* ev_timer;//连接超时事件
} remote_ctx_t;

typedef struct remote {
	int fd;
	buffer_t *buf;
	int direct;
	struct remote_ctx *recv_ctx;
	struct remote_ctx *send_ctx;
	struct server *server;
	struct sockaddr addr;
	int addr_len;
	uint32_t counter;
	event_base *base;
	bufferevent *bevent;
	int timeout;
} remote_t;
#endif