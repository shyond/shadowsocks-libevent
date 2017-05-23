#ifndef  _LOCAL_H
#define  _LOCAL_H

#include <WinSock2.h>
#include "encrypt.h"


typedef struct listen_ctx{
	struct event_base *base;
	int fd;
	int remote_num;
	int method;
	struct sockaddr **remote_addrs;
	int timeout;//���ӳ�ʱ
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
	struct event_base *base;
	struct bufferevent *bevent;
}server_t;

typedef struct remote_ctx {
    int connected;
	struct remote *remote;
	struct event* ev_timer;//���ӳ�ʱ�¼�
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
	struct event_base *base;
	struct bufferevent *bevent;
	int timeout;
} remote_t;
#endif