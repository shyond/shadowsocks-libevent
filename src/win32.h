#ifndef  _WIN32_H
#define  _WIN32_H

#include <WinSock2.h>
//#include <ws2tcpip.h>

void winsock_init(void);
void winsock_cleanup(void);

#endif