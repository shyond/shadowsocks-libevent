#include "local.h"
#include "jconf.h"
#include "utils.h"
#ifdef WIN32
#include "getopt.h"
#include "win32.h"
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

	while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:i:c:b:a:n:huUvA6",
		long_options, &option_index)) != -1) {

			switch(c){
			case 0:
				if (option_index == 0) {
					fast_open = 1;
				} else if (option_index == 1) {
					printf("initializing acl...");
					//acl = !init_acl(optarg);
				} else if (option_index == 2) {
					mtu = atoi(optarg);
					printf("set MTU to %d", mtu);
				} else if (option_index == 3) {
					mptcp = 1;
					printf("enable multipath TCP");
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
		printf("onetime authentication enabled");
	}

	//初始化win sock
#ifdef WIN32
	winsock_init();
#endif

	printf("initializing ciphers... %s", method);
	int m = enc_init(password, method);
}