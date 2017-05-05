#include "local.h"
#include "jconf.h"
#include "utils.h"
#include "encrypt.h"
#include "common.h"
#include <event2/event.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/thread.h>
#include "defer-internal.h"
#include "event-internal.h"
#include <event2/bufferevent_struct.h>
#include "bufferevent-internal.h"
#include "evthread-internal.h"

#ifdef WIN32
#include "getopt.h"
#include "win32.h"
#include <MSTcpIP.h>
#else
#include <getopt.h>
#endif


#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 2048
#endif

//int verbose        = 0;
int keep_resolving = 1;

static int fast_open = 0;
static int acl       = 0;

static int auth = 0;

static int get_sockaddr(struct sockaddr *skaddr,const char *host, const char *port)
{
	if(skaddr == NULL){
		return -1;
	}
	memset(skaddr,0,sizeof(struct sockaddr));
	((SOCKADDR_IN *)skaddr)->sin_family = AF_INET;
	((SOCKADDR_IN *)skaddr)->sin_port = ntohs(atoi(port));
	((SOCKADDR_IN *)skaddr)->sin_addr.S_un.S_addr = inet_addr(host);
	
	return 0;

}

static void server_recv_cb(struct bufferevent *bev, void *user_data)
{
	server_t *server = (server_t *)(user_data);
	server_ctx_t *server_recv_ctx = server->recv_ctx;
	remote_t *remote = server->remote;
	buffer_t *buf;
	size_t r;

	if (remote == NULL) {
		buf = server->buf;
	} else {
		buf = remote->buf;
	}

	r = bufferevent_read(bev,buf->array + buf->len,BUF_SIZE - buf->len);

}
static void server_send_cb(struct bufferevent *bev, void *user_data)
{

}
static void server_event_cb(struct bufferevent *bev, short what,void *user_data)
{

}
static server_t *new_server(int fd,listen_ctx_t *ctx)
{
	//初始化，分配内存
	server_t *server = (server_t *)ss_malloc(sizeof(server_t));
	memset(server,0,sizeof(server_t));
	server->recv_ctx = (server_ctx_t *)ss_malloc(sizeof(server_ctx_t));
	server->send_ctx = (server_ctx_t *)ss_malloc(sizeof(server_ctx_t));
	server->buf = (buffer_t *)ss_malloc(sizeof(buffer_t));

	server->stage = STAGE_INIT;
	server->recv_ctx->connected = 0;
	server->send_ctx->connected = 0;
	server->fd = fd;
	server->recv_ctx->server = server;
	server->send_ctx->server = server;
	server->listener = ctx;

	//加密方式存在
	if(ctx->method){
		server->e_ctx = (enc_ctx *)ss_malloc(sizeof(struct enc_ctx));
		server->d_ctx = (enc_ctx *)ss_malloc(sizeof(struct enc_ctx));
		enc_ctx_init(ctx->method, server->e_ctx, 1);//初始化加密模型
		enc_ctx_init(ctx->method, server->d_ctx, 0);//初始化解密模型
	}else{//加密方式不存在，采用table加密
		server->e_ctx = NULL;
		server->d_ctx = NULL;
	}
	 
	bufferevent *bev =  bufferevent_socket_new(ctx->base, fd,BEV_OPT_THREADSAFE|BEV_OPT_CLOSE_ON_FREE);
	if(bev == NULL){
		FATAL("bufferevent_socket_new failed!");
	}
	server->base = ctx->base;
	server->bevent = bev;
	bufferevent_setcb(bev, server_recv_cb, server_send_cb, server_event_cb, server);
	
	bufferevent_enable(bev, EV_READ | EV_PERSIST);//设置可接受数据

	return server;
}
static void listener_cb(evconnlistener *listener, evutil_socket_t fd,struct sockaddr *sock, int socklen, void *arg)
{
	listen_ctx_t *ctx = (listen_ctx_t *)(arg); 

	int opt = 1;
#ifndef WIN32
	setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
#else
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&opt, sizeof(opt));//
#ifdef SO_NOSIGPIPE
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (const char *)&opt, sizeof(opt));
#endif
#endif

	server_t *server = new_server(fd,ctx);
	//bufferevent *bev =  bufferevent_socket_new(ctx->base, fd,BEV_OPT_THREADSAFE|BEV_OPT_CLOSE_ON_FREE);
	//bufferevent_setcb(bev, conn_readcb, conn_writecb, conn_eventcb, ctx->base);
	//bufferevent_enable(bev, EV_READ | EV_PERSIST);
	//bufferevent_enable(bev,EV_WRITE);


}

int main(int argc,char** argv)
{
	int i, c;
	int pid_flags    = 0;
	int mtu          = 0;
	int mptcp        = 0;
	char *user       = NULL;
	char *local_port = NULL;
	char *local_addr = NULL;
	char *password   = NULL;
	char *timeout    = NULL;
	char *method     = NULL;
	char *pid_path   = NULL;
	char *conf_path  = NULL;
	char *iface      = NULL;

	int remote_num = 0;
	ss_addr_t remote_addr[MAX_REMOTE_NUM]; //远端地址
	char *remote_port = NULL;

	int option_index = 0;
	//长选项
	static struct option long_options[] = {
		{ "fast-open", no_argument,       0, 0 },
		{ "acl",       required_argument, 0, 0 },
		{ "mtu",       required_argument, 0, 0 },
		{ "mptcp",     no_argument,       0, 0 },
		{ "help",      no_argument,       0, 0 },
		{           0,                 0, 0, 0 }
	};

	USE_LOGFILE("ss_local.log");//使用日志文件


	while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:i:c:b:a:n:huUvA6",
		long_options, &option_index)) != -1) {

			switch(c){
			case 0:
				if (option_index == 0) {
					fast_open = 1;
				} else if (option_index == 1) {
					LOGI("initializing acl...");
					//acl = !init_acl(optarg);
				} else if (option_index == 2) {
					mtu = atoi(optarg);
					LOGI("set MTU to %d", mtu);
				} else if (option_index == 3) {
					mptcp = 1;
					LOGI("enable multipath TCP");
				} else if (option_index == 4) {
					usage();
					exit(EXIT_SUCCESS);
				}
				break;
			case 's':
				if (remote_num < MAX_REMOTE_NUM) {
					remote_addr[remote_num].host   = optarg;
					remote_addr[remote_num++].port = NULL;
				}
				break;
			case 'p':
				remote_port = optarg;
				break;
			case 'l':
				local_port = optarg;
				break;
			case 'k':
				password = optarg;
				break;
				/*
			case 'f':
				pid_flags = 1;
				pid_path  = optarg;
				break;
				*/
			case 't':
				timeout = optarg;
				break;
			case 'm':
				method = optarg;
				break;
				/*
			case 'c':
				conf_path = optarg;
				break;
			case 'i':
				iface = optarg;
				break;
				*/
			case 'b':
				local_addr = optarg;
				break;
			case 'a':
				user = optarg;
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'A':
				auth = 1;
				break;
			case '?':
				opterr = 1;
				break;
			}//end switch
	}//end while
	if (opterr) {
		usage();
		exit(EXIT_FAILURE);
	}
	//不走命令行参数，读取配置文件
	if (argc == 1) {
		if (conf_path == NULL) {
			//conf_path = DEFAULT_CONF_PATH;
		}
	}
	if(conf_path){//读取配置文件

	}

	//判断相关配置是否正确
	if (remote_num == 0 || remote_port == NULL ||
		local_port == NULL || password == NULL) {
			usage();
			exit(EXIT_FAILURE);
	}
	//默认加密方式 rc4-md5
	if (method == NULL) {
		method = "rc4-md5";
	}
	//默认超时时间60s
	if (timeout == NULL) {
		timeout = "60";
	}
	
	if(local_addr == NULL){
		local_addr = "127.0.0.1";
	}
	//开启一次认证
	if(auth){
		LOGI("onetime authentication enabled");
	}

	//初始化win sock
#ifdef WIN32
	winsock_init();
#endif

	LOGI("initializing ciphers... %s", method);
	int m = enc_init(password, method); //初始化key  method  table

	//初始化远端服务器地址
	listen_ctx_t lst_ctx;
	lst_ctx.remote_num = remote_num;
	lst_ctx.remote_addrs = (struct sockaddr **)ss_malloc(remote_num * sizeof(struct sockaddr*));
	memset((void *)lst_ctx.remote_addrs, 0, sizeof(struct sockaddr *) * remote_num);
	for (i = 0; i < remote_num; i++) {
		char *host = remote_addr[i].host;
		char *port = remote_addr[i].port == NULL ? remote_port : remote_addr[i].port;
		
		if (get_sockaddr(lst_ctx.remote_addrs[i], host,port) == -1) {
			FATAL("failed to resolve the provided hostname");
		}
	}
	lst_ctx.method = m;//加密方式


#ifdef WIN32

	evthread_use_windows_threads();

	struct event_config* cfg = event_config_new();
	event_config_set_flag(cfg,EVENT_BASE_FLAG_STARTUP_IOCP);

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	event_config_set_num_cpus_hint(cfg,si.dwNumberOfProcessors);

	event_base *base;
	base = event_base_new_with_config(cfg); 
	event_config_free(cfg);

	struct sockaddr_in sin;
	get_sockaddr((sockaddr *)&sin,local_addr,local_port);
	lst_ctx.base = base;

	evconnlistener* listener = evconnlistener_new_bind(base,listener_cb,&lst_ctx,LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE|LEV_OPT_THREADSAFE,-1, (struct sockaddr*)&sin,sizeof(struct sockaddr_in));

	if(!listener){

		FATAL("create listener failed!");
	}

	event_base_dispatch(base);

#endif

}