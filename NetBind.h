#ifndef   _NET_BIND_
#define   _NET_BIND_

#ifdef WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#elif _LINUX

#endif

#include <iostream>

typedef int (__cdecl *fp_crypt_callback)(unsigned char *data, int len1, unsigned char *edata, int *len2);

struct transocket 
{
#ifdef _WIN32
  SOCKET fd1;
  SOCKET fd2;
#elif _LINUX
  int fd1;
  int fd2;
#endif
  fp_crypt_callback crypt;
};

extern int TIMEOUT;//300 sec
#define MAXSIZE                20480
#define HOSTLEN                40
#define CONNECTNUM             5
#define BUF_LEN                1024

void transmitdata(void *data);
void sock5proxy(void *lp);
void closeallfd();
void bind2remote(int port1, char *remote, int port2);
void bind2bind(int port1, int port2);
void conn2conn(char *host1,int port1,char *host2,int port2);
int create_socket();
int create_server(int sockfd, int port);
int client_connect(int sockfd,char* server,int port);
int create_sock5proxy_server(int port);

#endif


