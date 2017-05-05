#include "win32.h"
#include "utils.h"

void winsock_init(void)
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int ret;
	wVersionRequested = MAKEWORD(2, 0);
	ret               = WSAStartup(wVersionRequested, &wsaData);
	if (ret != 0) {
		FATAL("Could not initialize winsock");
	}
	if (LOBYTE(wsaData.wVersion) != 1 || HIBYTE(wsaData.wVersion) != 1) {
		WSACleanup();
		FATAL("Could not find a usable version of winsock");
	}
}

void winsock_cleanup(void)
{
	WSACleanup();
}