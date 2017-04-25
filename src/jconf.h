#ifndef _JCONF_H
#define _JCONF_H

#define MAX_PORT_NUM 1024
#define MAX_REMOTE_NUM 10
#define MAX_CONF_SIZE 128 * 1024
#define MAX_DNS_NUM 4
#define MAX_CONNECT_TIMEOUT 10
#define MAX_REQUEST_TIMEOUT 60

typedef struct {
	char *host;
	char *port;
} ss_addr_t;

typedef struct {
	char *port;
	char *password;
} ss_port_password_t;


#endif