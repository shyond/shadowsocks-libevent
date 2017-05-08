#include "local.h"
#include "jconf.h"
#include "utils.h"
#include "encrypt.h"
#include "common.h"
#include <assert.h>
#include "sock5.h"
#include "http.h"
#include "tls.h"


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
#define BUF_SIZE 16384
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
static size_t get_sockaddr_len(struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		return sizeof(struct sockaddr_in);
	} else if (addr->sa_family == AF_INET6) {
		return sizeof(struct sockaddr_in6);
	}
	return 0;
}
static void close_and_free_server(server *server)
{

}
static void close_and_free_remote(remote *remote)
{

}
static void remote_timeout_cb(evutil_socket_t, short, void * arg)
{

}

static void remote_recv_cb(struct bufferevent *bev, void *user_data)
{

}
static void remote_send_cb(struct bufferevent *bev, void *user_data)
{

}
static void remote_event_cb(struct bufferevent *bev, short what,void *user_data)
{

}
static void set_remote_cb(remote_t *remote)
{
	remote->ev_timer = event_new(remote->base,NULL,EV_TIMEOUT,remote_timeout_cb,remote);
	bufferevent *bev = bufferevent_socket_new(remote->base, remote->fd,BEV_OPT_THREADSAFE|BEV_OPT_CLOSE_ON_FREE);

	bufferevent_setcb(bev,remote_recv_cb,remote_send_cb,remote_event_cb,remote);

	remote->bevent = bev;
}
static remote_t *new_remote(listen_ctx* listener,int fd,int timeout)
{
	remote_t *remote;
	remote = (remote_t *)ss_malloc(sizeof(remote_t));

	memset(remote, 0, sizeof(remote_t));

	remote->buf					= (buffer_t *)ss_malloc(sizeof(buffer_t));
	remote->recv_ctx            = (remote_ctx *)ss_malloc(sizeof(remote_ctx_t));
	remote->send_ctx            = (remote_ctx *)ss_malloc(sizeof(remote_ctx_t));
	balloc(remote->buf, BUF_SIZE);
	memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
	memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
	remote->recv_ctx->connected = 0;
	remote->send_ctx->connected = 0;
	remote->fd                  = fd;
	remote->recv_ctx->remote    = remote;
	remote->send_ctx->remote    = remote;

	return remote;
}
static remote_t *create_remote(listen_ctx *listener,struct sockaddr *addr)
{
	struct sockaddr *remote_addr;

	int index = rand() % listener->remote_num;
	if (addr == NULL) {
		remote_addr = listener->remote_addrs[index];
	} else {
		remote_addr = addr;
	}

	int remotefd = socket(remote_addr->sa_family, SOCK_STREAM, IPPROTO_TCP);

	if (remotefd == -1) {
		LOGE("socket new error");
		return NULL;
	}

	int opt = 1;
	setsockopt(remotefd, IPPROTO_TCP, TCP_NODELAY, (const char *)&opt, sizeof(opt));

	// Setup
#ifdef WIN32
	int iMode = 1; 
	int iasd=ioctlsocket(remotefd,FIONBIO,(u_long FAR*) &iMode);
#else
	setnonblocking(remotefd);
#endif

	remote_t *remote = new_remote(listener,remotefd, listener->timeout);
	remote->addr_len = get_sockaddr_len(remote_addr);
	memcpy(&(remote->addr), remote_addr, remote->addr_len);
	remote->base = listener->base;

	return remote;
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
	
	
	size_t read_len = evbuffer_get_length(bufferevent_get_input(bev));//获取接收字节大小
	
	size_t left =  buf->capacity -buf->len;//获取剩余容量
	//重新分配内存，libevent max_io_read_buffer =16k,buf capacity = 16k,
	//每次加密完buf->len = 0;所以很少出现left < read_len
	if(left < read_len){

		brealloc(buf,0,read_len + buf->len);
	}

	r = bufferevent_read(bev,buf->array + buf->len,read_len);//一次性读完,bufferevent_read有内容不会自动回调
	assert(r == read_len);
	buf->len += r;

	while(1){
		
		//sock5 .客户端发送
		if(server->stage == STAGE_INIT){

			method_select_response response;
			response.ver = SVERSION;
			response.method = 0;//无需认证
			char *send_buf = (char *)&response;
			//直接发送,不会反悔-1
			send(server->fd, send_buf, sizeof(response), 0);
			server->stage = STAGE_HANDSHAKE;
			//off为客户第一次发送的字节数
			//“协议版本号（1字节）+客户端支持的认证方式个数（1字节）+客户端支持的认证方式列表（1至255字节）”。 
			int off = (buf->array[1] & 0xff) + 2;
			if (buf->array[0] == 0x05 && off < (int)(buf->len)) {
				memmove(buf->array, buf->array + off, buf->len - off);
				buf->len -= off;
				continue;
			}

			buf->len = 0;
			return ;
		}else if(server->stage == STAGE_HANDSHAKE || server->stage == STAGE_PARSE){
			struct socks5_request *request = (struct socks5_request *)buf->array;
			struct sockaddr_in sock_addr;
			memset(&sock_addr, 0, sizeof(sock_addr));

			//only supported CMD=CONNECT
			if(request->cmd != 1){
				LOGE("unsupported cmd: %d", request->cmd);
				struct socks5_response response;
				response.ver  = SVERSION;
				response.rep  = CMD_NOT_SUPPORTED;
				response.rsv  = 0;
				response.atyp = 1;
				char *send_buf = (char *)&response;
				send(server->fd, send_buf, 4, 0);
				close_and_free_remote(remote);
				close_and_free_server(server);
				return ;
			}
			//CMD = CONNECT
			if (server->stage == STAGE_HANDSHAKE) {
				struct socks5_response response;
				response.ver  = SVERSION;
				response.rep  = 0;
				response.rsv  = 0;
				response.atyp = 1;

				buffer_t resp_to_send;
				buffer_t *resp_buf = &resp_to_send;
				balloc(resp_buf, BUF_SIZE);

				memcpy(resp_buf->array, &response, sizeof(struct socks5_response));
				//sock_addr = 0
				memcpy(resp_buf->array + sizeof(struct socks5_response),&sock_addr.sin_addr, sizeof(sock_addr.sin_addr));
				memcpy(resp_buf->array + sizeof(struct socks5_response) +sizeof(sock_addr.sin_addr),&sock_addr.sin_port, sizeof(sock_addr.sin_port));

				int reply_size = sizeof(struct socks5_response) +
					sizeof(sock_addr.sin_addr) + sizeof(sock_addr.sin_port);

				int s = send(server->fd, resp_buf->array, reply_size, 0);
				bfree(resp_buf);

				if (s < reply_size) {
					LOGE("failed to send fake reply");
					close_and_free_remote(remote);
					close_and_free_server(server);
					return;
				}
			}
/*
		    +----+-----+-------+------+----------+----------+ 
		    | VER| CMD | RSV   | ATYP |  DST.ADDR|  DST.PORT|
			+----+-----+-------+------+----------+----------+ 
			| 1  | 1   | X'00' | 1    | variable |      2   |
			+----+-----+-------+------+----------+----------+ 
*/
			char host[257], ip[INET6_ADDRSTRLEN], port[16];

			buffer_t ss_addr_to_send;
			buffer_t *abuf = &ss_addr_to_send;
			balloc(abuf, BUF_SIZE);

			abuf->array[abuf->len++] = request->atyp;
			int atyp = request->atyp;

			//IPv4
			if(atyp == 1){
				//abuf = atyp + DST.ADDR(ipv4) + DST.PORT(2B)
				size_t in_addr_len = sizeof(struct in_addr);
				memcpy(abuf->array + abuf->len, buf->array + 4, in_addr_len + 2);
				abuf->len += in_addr_len + 2;
			}else if(atyp == 3){
				//
				// Domain name
				//DST.ADDR = len_domain(1B) + Domain
				uint8_t name_len = *(uint8_t *)(buf->array + 4);//获取域名长度
				abuf->array[abuf->len++] = name_len;
				memcpy(abuf->array + abuf->len, buf->array + 4 + 1, name_len + 2);
				abuf->len += name_len + 2;

				//abuf = atyp + DST.ADDR(ipv4) + DST.PORT(2B)
			}else if(atyp == 4){
				//IPv6
				bfree(abuf);
				close_and_free_remote(remote);
				close_and_free_server(server);
				LOGI("sock5 server not supported IPV6");
				return;
			}else{
				bfree(abuf);
				LOGE("unsupported addrtype: %d", request->atyp);
				close_and_free_remote(remote);
				close_and_free_server(server);
				return;
			}

			
			size_t abuf_len  = abuf->len;
			//对于ipv4和ipv6若发现domain，将其构造成atyp = 3
			if (atyp == 1 || atyp == 4) {
				char *hostname;
				uint16_t p = ntohs(*(uint16_t *)(abuf->array + abuf->len - 2));
				int ret    = 0;
				if (p == http_protocol->default_port)
					ret = http_protocol->parse_packet(buf->array + 3 + abuf->len,buf->len - 3 - abuf->len, &hostname);
				//Server Name Indication
				//从tls client_hello的extensions中获取域名
				else if (p == tls_protocol->default_port)
					ret = tls_protocol->parse_packet(buf->array + 3 + abuf->len,buf->len - 3 - abuf->len, &hostname);
				if (ret == -1) {
					//对于http请求，等待http完整头的到来
					//对于https请求，等待client_hello的到来
					server->stage = STAGE_PARSE;
					bfree(abuf);
					return;
				} else if (ret > 0) {
					
					// Reconstruct address buffer
					abuf->len                = 0;
					abuf->array[abuf->len++] = 3;
					abuf->array[abuf->len++] = ret;
					memcpy(abuf->array + abuf->len, hostname, ret);
					abuf->len += ret;
					p          = htons(p);
					memcpy(abuf->array + abuf->len, &p, 2);
					abuf->len += 2;
					ss_free(hostname);
				}
			}

			server->stage = STAGE_STREAM;
			buf->len -= (3 + abuf_len);
			buf->len -= (3 + abuf_len);
			if (buf->len > 0) {
				memmove(buf->array, buf->array + 3 + abuf_len, buf->len);
			}

			{
				//可在此添加白名单
			}
			
			if(remote == NULL){

				remote = create_remote(server->listener,NULL);
			}
			server->remote = remote;
			remote->server = server;
			set_remote_cb(remote);

			//一次认证
			if (!remote->direct) {
				if (auth) {
					abuf->array[0] |= ONETIMEAUTH_FLAG;
					ss_onetimeauth(abuf, server->e_ctx->evp.iv, BUF_SIZE);
				}

				if (buf->len > 0 && auth) {
					ss_gen_hash(buf, &remote->counter, server->e_ctx, BUF_SIZE);
				}

				brealloc(remote->buf, buf->len + abuf->len, BUF_SIZE);
				memcpy(remote->buf->array, abuf->array, abuf->len);
				remote->buf->len = buf->len + abuf->len;

				if (buf->len > 0) {
					memcpy(remote->buf->array + abuf->len, buf->array, buf->len);
				}
			} else {
				if (buf->len > 0) {
					memcpy(remote->buf->array, buf->array, buf->len);
					remote->buf->len = buf->len;
				}
			}
		}//server->stage == STAGE_HANDSHAKE || server->stage == STAGE_PARSE
		else if(server->stage == STAGE_STREAM){
			if (remote == NULL) {
				LOGE("invalid remote");
				close_and_free_server(server);
				return;
			}
			//
			if (!remote->direct && remote->send_ctx->connected && auth) {
				ss_gen_hash(remote->buf, &remote->counter, server->e_ctx, BUF_SIZE);
			}
		}
	}

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
	balloc(server->buf, BUF_SIZE);
	memset(server->recv_ctx, 0, sizeof(server_ctx_t));
	memset(server->send_ctx, 0, sizeof(server_ctx_t));

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
	lst_ctx.timeout = atoi(timeout);

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