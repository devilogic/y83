#include "NetBind.h"
#include "Configure.h"
#include <errno.h>
#include "CryptIt.h"

#ifdef _WIN32
#include "..\..\fr1140m\public\LogFilePort.h"
#elif _LINUX
#define SOCKET int
#define HANDLE int
#endif

#include <vector>

int TIMEOUT;//300 sec

extern std::vector<int> g_xSocket;
extern CONFIGURE_STRUCT g_Configure;

// --------------------------------------------------
void bind2bind(int port1, int port2)
{
    SOCKET fd1,fd2, sockfd1, sockfd2;
    struct sockaddr_in client1,client2;
    int size1,size2;
    HANDLE hThread=NULL;
    transocket sock;
    DWORD dwThreadID;
	
    if((fd1=create_socket())==0) return;
    if((fd2=create_socket())==0) return;
    XLOGI("[+] Listening port %d ......\r\n",port1);
    fflush(stdout);
    if(create_server(fd1, port1)==0)
    {
        closesocket(fd1);
        return;
    }
    XLOGI("[+] Listen OK!\r\n");
    XLOGI("[+] Listening port %d ......\r\n",port2);
    fflush(stdout);
    if(create_server(fd2, port2)==0)
    {
		closesocket(fd1);
        closesocket(fd2);
        return;
    }
    XLOGI("[+] Listen OK!\r\n");
    size1=size2=sizeof(struct sockaddr);
    while(1)
    {
        XLOGI("[+] Waiting for Client on port:%d ......\r\n",port1);
        if((sockfd1 = accept(fd1,(struct sockaddr *)&client1,&size1))<0)
		{
			XLOGI("[-] Accept1 error.\r\n");
			continue;
		}

	if (g_Configure.bL2LCrypt[0] == CRYPT_IT)
	    SetSockToXList((int)sockfd1);

        XLOGI("[+] Accept a Client on port %d from %s ......\r\n", port1, inet_ntoa(client1.sin_addr));
        XLOGI("[+] Waiting another Client on port:%d....\r\n", port2);

_start_accept_fd2:
		if((sockfd2 = accept(fd2, (struct sockaddr *)&client2, &size2))<0)
		{
			XLOGI("[-] Accept2 error.\r\n");
			goto _start_accept_fd2;
			//closesocket(sockfd1);
			//DeleteSockFromXList((int)sockfd1);
			//continue;
		}

		// 设定套接字是否加解密
		if (g_Configure.bL2LCrypt[1] == CRYPT_IT)
			SetSockToXList( (int)sockfd2 );

        XLOGI("[+] Accept a Client on port %d from %s\r\n",port2, inet_ntoa(client2.sin_addr));
        XLOGI("[+] Accept Connect OK!\r\n");
        sock.fd1 = sockfd1;
        sock.fd2 = sockfd2;
        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)transmitdata, (LPVOID)&sock, 0, &dwThreadID); 
        if(hThread == NULL) 
        {
            TerminateThread(hThread, 0);
            return;
        }
		XLOGI("[+] CreateThread OK!\r\n\n");
		if (g_Configure.bL2CSync == TRUE) //同步
			WaitForSingleObject(hThread, -1);
		else	// 异步
			Sleep(1000);
	}
}

void bind2remote(int port1, char *remote, int port2)
{
	SOCKET fd1,fd2, sockfd1;
	struct sockaddr_in client1,client2;
	int size1,size2;
#ifdef WIN32
	HANDLE hThread=NULL;
#else
	int hThread = 0;
#endif
	transocket sock;
	DWORD dwThreadID;

	sock.crypt = NULL;

	if((fd1=create_socket())==0) return;
	if((fd2=create_socket())==0) return;
	
	// 创建服务器
	if(create_server(fd1, port1)==0)
	{
		closesocket(fd1);
		return;
	}
	XLOGI("[+] Listen OK!\r\n");

	size1=size2=sizeof(struct sockaddr);
	while(1)
	{
		XLOGI("[+] Waiting for Client on port:%d ......\r\n",port1);
		int _sockfd1 = -1;
		if((_sockfd1 = (int)accept(fd1,(struct sockaddr *)&client1,&size1))<0)
		{
			XLOGI("[-] Accept1 error.\r\n");
			continue;
		}
		sockfd1 = (SOCKET)_sockfd1;

		// 设定套接字是否加解密
		if (g_Configure.bL2CCrypt[0] == CRYPT_IT)
			SetSockToXList( (int)sockfd1 );

		XLOGI("[+] Accept Connect OK!\r\n");
		sock.fd1 = sockfd1;

		XLOGI("[+] Connect remote:%s:%d ......\r\n",remote, port2);

		// 链接远程
		if ( client_connect(fd2, remote, port2 ) == 0 ) {
			// 这里是不是应该循环链接一下尝试
			closesocket(sockfd1);
			DeleteSockFromXList((int)sockfd1);
			continue;
		}
		XLOGI("[+] Connect OK!\r\n");
		sock.fd2 = fd2;

		// 设定套接字是否加解密
		if (g_Configure.bL2CCrypt[1] == CRYPT_IT)
			SetSockToXList( (int)fd2 );

		// 开辟传输线程
#ifdef WIN32
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)transmitdata, (LPVOID)&sock, 0, &dwThreadID); 
		if(hThread == NULL) 
		{
			TerminateThread(hThread, 0);
			return;
		}
		XLOGI("[+] Create Thread OK!\r\n\n");
		if (g_Configure.bL2CSync == TRUE) //同步
			WaitForSingleObject(hThread, -1);
		else	// 异步
			Sleep(1000);
		sockfd1 = fd2 = INVALID_SOCKET;
		fd2=create_socket();// 重新创建一个套接字
#else
		
#endif
	}

	return;
}

void conn2conn(char *host1,int port1,char *host2,int port2)
{
	SOCKET sockfd1,sockfd2;
	
	HANDLE hThread=NULL;
	transocket sock;
	DWORD dwThreadID;
	fd_set fds;
	int l;
	char buffer[MAXSIZE];

	while(1)
	{
_start:
		// 创建两个套接字
		if((sockfd1=create_socket())==0) return;
		if((sockfd2=create_socket())==0) return;

		XLOGI("[+] Make a Connection to %s:%d....\r\n",host1,port1);

		// 链接第一个主机
		if(client_connect(sockfd1,host1,port1)==0) 
	  	{
		  	closesocket(sockfd1);
		  	closesocket(sockfd2);
			sockfd1 = sockfd2 = INVALID_SOCKET;
#ifdef _WIN32
			Sleep(1000);
#else
#endif
		  	continue;
		}

		// 设定套接字是否加解密
		if (g_Configure.bC2CCrypt[0] == CRYPT_IT)
			SetSockToXList( (int)sockfd1 );

		// 判断是等待端口1来了数据才链接端口2,还是直接链接
		if (g_Configure.bNotWaitRecvToConnectPort2 == FALSE)
		{
			// 如果这里从host:port1有数据传送过来,再连接到host2,port2
			l=0;
			memset(buffer,0,MAXSIZE);
			while(1)
			{
				FD_ZERO(&fds);
				FD_SET(sockfd1, &fds);
				
				if (select(sockfd1+1, &fds, NULL, NULL, NULL) == SOCKET_ERROR) 
				{
					if (errno == WSAEINTR) continue;
					break;
				}
				if (FD_ISSET(sockfd1, &fds)) 
				{
					l=recv(sockfd1, buffer, MAXSIZE, 0);
					break;
				}
				Sleep(5);
			}


			if(l<=0) 
			{
	#ifdef _WIN32
				XLOGI("[-] There is a error:%d...Create a new connection.\r\n", WSAGetLastError());
	#else
				XLOGI("[-] There is a error...Create a new connection.\r\n");
	#endif
				// 只要链接1断开必然断开链接2
				closesocket(sockfd1);
				DeleteSockFromXList((int)sockfd1);
				if (sockfd2 != INVALID_SOCKET)
				{
					closesocket(sockfd2);
					DeleteSockFromXList((int)sockfd1);
				}
				sockfd1 = sockfd2 = INVALID_SOCKET;
				continue;
			}
		}/* end if */

		while(1)
		{
			XLOGI("[+] Connect OK!\r\n");
			XLOGI("[+] Make a Connection to %s:%d....\r\n", host2,port2);
			if(client_connect(sockfd2,host2,port2)==0) 
	  		{
				closesocket(sockfd1);
				DeleteSockFromXList((int)sockfd1);
				if (sockfd2 != INVALID_SOCKET)
				{
					closesocket(sockfd2);
					DeleteSockFromXList((int)sockfd1);
				}
				sockfd1 = sockfd2 = INVALID_SOCKET;
				//continue;
				goto _start;
			}

			// 设定套接字是否加解密
			if (g_Configure.bC2CCrypt[1] == CRYPT_IT)
				SetSockToXList( (int)sockfd2 );

			// 只有在等待状况下才发送
			if (g_Configure.bNotWaitRecvToConnectPort2 == FALSE)
			{
				if(send(sockfd2,buffer,l,0)==SOCKET_ERROR)
				{	
					XLOGI("[-] Send failed.\r\n");
					continue;
				}

				l=0;
				memset(buffer,0,MAXSIZE);
			}
			break;
		}/* end while */
	
		XLOGI("[+] All Connect OK!\r\n");

		sock.fd1 = sockfd1;
		sock.fd2 = sockfd2;

#ifdef WIN32
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)transmitdata, (LPVOID)&sock, 0, &dwThreadID); 
		if(hThread == NULL) 
		{
			TerminateThread(hThread, 0);
			closesocket(sockfd1);
			DeleteSockFromXList((int)sockfd1);
			closesocket(sockfd2);
			DeleteSockFromXList((int)sockfd2);
			return;
		}
		XLOGI("[+] CreateThread OK!\r\n\n");
		if (g_Configure.bC2CSync == TRUE) //同步
			WaitForSingleObject(hThread, -1);
		else	// 异步
			Sleep(1000);
#else
#endif
	}
}

void closeallfd()
{
    int i;
    XLOGI("[+] Let me exit ......\r\n");
    //fflush(stdout);
    for(i=3; i<256; i++)
    {
        closesocket(i);
    }
	
    XLOGI("[+] All Right!\r\n");
}
int create_socket()
{  
    int sockfd;
	
    sockfd=socket(AF_INET,SOCK_STREAM,0);
    if(sockfd<0)
    {
#ifdef WIN32
		XLOGI("[-] Create socket error:%d.\r\n", WSAGetLastError());
#else
		XLOGI("[-] Create socket error.\r\n");
#endif
		int a = WSAGetLastError();
        return(0);
    }
    
    return(sockfd);    
}
int create_server(int sockfd,int port)
{
    struct sockaddr_in srvaddr;
    int on=1;
    
    memset(&srvaddr, 0, sizeof(struct sockaddr));
    srvaddr.sin_port=htons(port);
    srvaddr.sin_family=AF_INET;
    srvaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	
    setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR, (char*)&on,sizeof(on));  //so I can rebind the port
    if(bind(sockfd,(struct sockaddr *)&srvaddr,sizeof(struct sockaddr))<0)
    {
        XLOGI("[-] Socket bind error.\r\n");
        return(0);
    }
    if(listen(sockfd,CONNECTNUM)<0)
    {
        XLOGI("[-] Socket Listen error.\r\n");
        return(0);
    }
    
    return(1);
}
int client_connect(int sockfd,char* server,int port)
{
	struct sockaddr_in cliaddr;
	struct hostent *host;
	if(!(host=gethostbyname(server)))
	{
		XLOGI("[-] Gethostbyname(%s) error:%s\n",server,strerror(errno));
		return(0);
	}      
	
	memset(&cliaddr, 0, sizeof(struct sockaddr));
	cliaddr.sin_family=AF_INET;
	cliaddr.sin_port=htons(port);
	cliaddr.sin_addr=*((struct in_addr *)host->h_addr);
	
	if(connect(sockfd,(struct sockaddr *)&cliaddr,sizeof(struct sockaddr))<0)
	{
		XLOGI("[-] Connect error.\r\n");
		return(0);
	}
	return(1);
}

int create_sock5proxy_server(int port)
{
	SOCKET listenSocket, acceptSocket;
	SOCKADDR_IN acceptAddr;
	int iAcceptAddrLen;
	HANDLE hThread = NULL;
	DWORD dwThreadId = 0;

	if((listenSocket = create_socket()) == 0) return false;

	XLOGI("[+] Listening port %d ......\r\n", port);

	if(create_server(listenSocket, port)==0)
	{
		closesocket(listenSocket);
		return -1;
	}

	XLOGI("[+] Listen OK!\r\n");
	memset( &acceptAddr, 0, sizeof(acceptAddr));

	while(true)
	{
		XLOGI("[+] Waiting for Client ......\r\n");
		iAcceptAddrLen = sizeof(acceptAddr);
		acceptSocket = accept( listenSocket, (SOCKADDR*)&acceptAddr, &iAcceptAddrLen);
		if( acceptSocket != INVALID_SOCKET)
		{
#ifdef WIN32
			hThread = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)sock5proxy, (LPVOID)acceptSocket, 0, &dwThreadId);
			if( hThread != NULL)
			{
				Sleep(1);
				CloseHandle(hThread);
			}
#else
#endif
		}
	}

	if( listenSocket != INVALID_SOCKET)
		closesocket( listenSocket);

	return 0;
}

//////////////////////////////////////////////////////////////////////////
void sock5proxy(void *lp)
{
	SOCKET s = (SOCKET)lp;
	
	char szRecvBuff[MAXSIZE] = {0};
	char szSendBuff[MAXSIZE] = {0};
	DWORD dwLen = 0;
	
	struct sockaddr_in saClient;
	int nsaClientLen = 0;
	getpeername( s, (struct sockaddr *)&saClient, &nsaClientLen);
	XLOGI("[+] New connection from %s:%d !!\n", inet_ntoa(saClient.sin_addr), ntohs(saClient.sin_port));
	
	int port = 0;
	struct in_addr addr;
	struct sockaddr_in sa2;

	SOCKET sock = INVALID_SOCKET;

	memset(szRecvBuff, 0, sizeof(szRecvBuff));
	dwLen = recv(s, szRecvBuff, sizeof(MAXSIZE), 0);

	/*
	CMD_SHELL_PACKET csp;
	memset( (CMD_SHELL_PACKET*)&csp, 0, sizeof(csp));

	memset( szRecvBuff, 0, sizeof(szRecvBuff));
	dwLen = recv( s, szRecvBuff, sizeof(csp), 0);

	if( dwLen == sizeof(csp))
	{
		printf("[+] CMD_SHELL_PACKET recved!\n");
		memcpy( (CMD_SHELL_PACKET*)&csp, szRecvBuff, sizeof(csp));
		if( memcmp( csp.szHeader, CMD_SHELL_HEADER, sizeof(csp.szHeader)) == 0)
		{
			if( csp.eShellType == BIND_SHELL)
			{
				csp.bResult = true;
				send( s, (char *)&csp, sizeof(csp), 0);
				shutdown( s, 2);
				closesocket(s);
				BindShell( csp.nPort, "password");
				return 0;
			}
			if( csp.eShellType == BACK_SHELL)
			{
				if( BackShell( csp.dwHostIp, csp.nPort) == true)
					csp.bResult = true;
			}
			
			send( s, (char *)&csp, sizeof(csp), 0);
		}
		shutdown( s, 2);
		closesocket(s);
		return 0;
	}
	*/

	// 接收3字节的SOCK5代理协议头
	if( dwLen != 3)
	{
		XLOGI("[-] Not 3 bytes data, close connection!\n");
		goto _end;
	}
	
	// VER:5|NMETHODS:1|METHODS:0
	if( szRecvBuff[0] == 5 && szRecvBuff[1] == 1 && szRecvBuff[2] == 0)
	{
		// 发送2字节的应答包
		szSendBuff[0] = 5;
		szSendBuff[1] = 0;
		dwLen = send( s, szSendBuff, 2, 0);
		if( dwLen != 2)
		{
			XLOGI("[-] Send 2 bytes data failed! Error:%d\n", WSAGetLastError());
			goto _end;
		}
	}
	else
	{
		// 错误的SOCK5请求
		XLOGI("[-] The 3 bytes data not the correct format!\n");
		goto _end;
	}
	
	// 获取远程地址与端口从客户端
	memset( szRecvBuff, 0, sizeof(szRecvBuff));
	dwLen = recv( s, szRecvBuff, sizeof(szRecvBuff)-1, 0);
	if( dwLen == SOCKET_ERROR || dwLen == 0)
	{
		goto _end;
	}
	
	//--------------------------------------------------------------------------------
	// 检查是否是SOCK5的数据

	// 这个服务器对于验证只解析"CONNECT"与"UDP ASSOCIATE"命令,地址只接受IP4地址链接与域名,不接收IP6
	// VER:5|CMD:1or3|RSV:0|ATYP:1or3|DST.ADDR|DST.PORT
	if( szRecvBuff[0] != 5 || szRecvBuff[2] != 0 )
	{
		goto _end;
	}
	if( szRecvBuff[1] != 1 && szRecvBuff[1] != 3)
	{
		goto _end;
	}
	
	//--------------------------------------------------------------------------------
	// 获取要链接的地址
	// IP4地址
	if( szRecvBuff[3] == 1)
	{
		addr.S_un.S_un_b.s_b1=szRecvBuff[4];
		addr.S_un.S_un_b.s_b2=szRecvBuff[5];
		addr.S_un.S_un_b.s_b3=szRecvBuff[6];
		addr.S_un.S_un_b.s_b4=szRecvBuff[7];
		port=unsigned(szRecvBuff[8]&0xff)<<8;
		port+=unsigned(szRecvBuff[9]&0xff);
		sa2.sin_addr.s_addr = addr.s_addr;
	}
	// 域名
	else if( szRecvBuff[3] == 3)
	{
		int nServerLen = szRecvBuff[4];
		char *chServerIp = new char[nServerLen+1]; 
		memset(chServerIp, 0, nServerLen+1); 
		memcpy(chServerIp, szRecvBuff+5, nServerLen); 
		char *szRemoteHost = (char *)chServerIp; 
		printf("[+] RemoteHost: %s\n", szRemoteHost);
		int nRemotePort = 0;
		memcpy(&nRemotePort, szRecvBuff+nServerLen+5, 2); 
		port = ntohs(nRemotePort); 
		struct hostent *lpHostEntry=NULL;
		char *szIPAddress=NULL;
		lpHostEntry = gethostbyname( szRemoteHost); 
		if(chServerIp) delete chServerIp;
		if( lpHostEntry == NULL) 
		{ 
			XLOGI("[-] Can't get ip of: %s ! Error:%d\n", szRemoteHost, WSAGetLastError()); 
			goto _end;
		}  
		szIPAddress = inet_ntoa(*(LPIN_ADDR)*(lpHostEntry->h_addr_list));
		sa2.sin_addr.s_addr = inet_addr( szIPAddress);
	}
	else
	{
		XLOGI("[-] Unknow address format!\n");
		goto _end;
	}				
	
	sa2.sin_family = AF_INET;
	sa2.sin_port = htons( port);
	
	u_long ul = 1;
	int iErr = 0;
	struct sockaddr_in LocalAddr;
	int nLen = sizeof(struct sockaddr);
	
	//--------------------------------------------------------------------------------
	if( szRecvBuff[1] == 1) //connect
	{	
		sock = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if( sock == INVALID_SOCKET) goto _end;
		
		iErr = connect( sock, (struct sockaddr *)&sa2, sizeof(sa2));
		if( iErr == SOCKET_ERROR) 
		{
			XLOGI("[-] Connect to %s:%d FAILED! Error:%d\n", inet_ntoa(sa2.sin_addr), port, WSAGetLastError());
			goto _end;
		}
		XLOGI("[+] Connect to %s:%d SUCCEED!\n", inet_ntoa(sa2.sin_addr), port);
	}
	else if( szRecvBuff[1] == 3) //udp
	{
		XLOGI("[+] Udp sock!\n");
		
		sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if( sock == INVALID_SOCKET) 
		{
			goto _end;
		}
		
		XLOGI("[+] Connect to %s:%d SUCCEED!\n", inet_ntoa(sa2.sin_addr), port);
	}
	
	if(getsockname(sock, (struct sockaddr *)&LocalAddr, &nLen)<0)
		getpeername( sock, (struct sockaddr *)&LocalAddr, &nLen);
	else
		XLOGI("[+] got, ip:%s, port:%d\r\n",inet_ntoa(LocalAddr.sin_addr),ntohs(LocalAddr.sin_port));

	// 填充回应请求,发送给客户端
	szSendBuff[0] = 5;
	szSendBuff[1] = 0;
	szSendBuff[2] = 0;
	szSendBuff[3] = 1;
	memcpy( szSendBuff+4, &(LocalAddr.sin_addr), 4);
	memcpy( szSendBuff+4+4, &(LocalAddr.sin_port), 2);
	send( s, szSendBuff, 10, 0);
	iErr = ioctlsocket( s, FIONBIO, (unsigned long*)&ul);
	iErr = ioctlsocket( sock, FIONBIO, (unsigned long*)&ul);
	
	//--------------------------------------------------------------------------------
	// cmd = connect
	if( szRecvBuff[1] == 1)
	{
		transocket mysock;
		mysock.fd1 = s;
		mysock.fd2 = sock;
		HANDLE hThread = NULL;
		DWORD dwThreadId = 0;
		
#ifdef WIN32
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)transmitdata, (LPVOID)&mysock, 0, &dwThreadId); 
		if( hThread != NULL)
		{
			XLOGI("[+] CreateThread to Transmit Data ok!\n");
			Sleep(1000);
			CloseHandle(hThread);
		}
		Sleep(300);
#else
#endif
	}
	
	//--------------------------------------------------------------------------------
	// cmd = udp
	if( szRecvBuff[1] == 3)
	{
		struct timeval timeset;
		timeset.tv_sec = TIMEOUT;
		timeset.tv_usec = 0;
		fd_set r, w;
		char szUdpBuff[10240] = {0};
		nLen = 0;
		int nFromLen = sizeof(struct sockaddr);
		
		while(1)
		{
			if(s == INVALID_SOCKET || sock == INVALID_SOCKET) 
			{
				if( s != INVALID_SOCKET) closesocket( s);
				if( sock != INVALID_SOCKET) closesocket( sock);
				break;
			}
			Sleep(1);
			FD_ZERO(&r);
			FD_ZERO(&w);
			FD_SET(s, &r);
			FD_SET(s, &w);
			select(s+1, &r, &w, NULL, &timeset);
			
			if( FD_ISSET(s, &r) )
			{
				nLen = recv( s, szUdpBuff, sizeof(szUdpBuff)-1, 0);
				if( nLen > 0)
				{
					sendto( sock, szUdpBuff, nLen, 0, (struct sockaddr *)&sa2, sizeof(struct sockaddr));
				}
			}
			
			if( FD_ISSET(s, &w) )
			{
				memset( szUdpBuff, 0, sizeof(szUdpBuff));
				nLen = recvfrom( sock, szUdpBuff+10, sizeof(szUdpBuff)-1, 0, (struct sockaddr *)&sa2, &nFromLen);
				szUdpBuff[3] = 1;
				memcpy( szUdpBuff+4, &(sa2.sin_addr), 4 );
				memcpy( szUdpBuff+4+4, &(sa2.sin_port), 2);
				send( s, szUdpBuff, nLen+10, 0);
			}
		}
	}

_end:
	//Sleep(300);
	//if(s != INVALID_SOCKET) 
	//{
	//	shutdown(s, 2);
	//	closesocket(s);
	//}
	//if(sock != INVALID_SOCKET) 
	//{
	//	shutdown(sock, 2);
	//	closesocket(sock);
	//}
  return;
}

// 线程传输函数
void transmitdata(void *data)
{
    SOCKET fd1, fd2;
    transocket *sock;
    struct timeval timeset;
    fd_set readfd,writefd;
    int result,i=0;
    char read_in1[MAXSIZE],send_out1[MAXSIZE];
    char read_in2[MAXSIZE],send_out2[MAXSIZE];
    int read1=0,totalread1=0,send1=0;
    int read2=0,totalread2=0,send2=0;
    int sendcount1,sendcount2;
    int maxfd;
    struct sockaddr_in client1,client2;
    int structsize1,structsize2;
    char host1[20],host2[20];
    int port1=0,port2=0;
    char tmpbuf[100];
    sock = (transocket *)data;
    fd1 = sock->fd1;
    fd2 = sock->fd2;
    memset(host1,0,20);
    memset(host2,0,20);
    memset(tmpbuf,0,100);
    structsize1=sizeof(struct sockaddr);
    structsize2=sizeof(struct sockaddr);
    
    if(getpeername(fd1,(struct sockaddr *)&client1,&structsize1)<0)
    {
        strcpy(host1, "fd1");
    }
    else
    {    
		//XLOGI("[+]got, ip:%s, port:%d\r\n",inet_ntoa(client1.sin_addr),ntohs(client1.sin_port));
        strcpy(host1, inet_ntoa(client1.sin_addr));
        port1=ntohs(client1.sin_port);
    }
    if(getpeername(fd2,(struct sockaddr *)&client2,&structsize2)<0)
    {
        strcpy(host2,"fd2");
    }
    else
    {    
		// XLOGI("[+]got, ip:%s, port:%d\r\n",inet_ntoa(client2.sin_addr),ntohs(client2.sin_port));
        strcpy(host2, inet_ntoa(client2.sin_addr));
        port2=ntohs(client2.sin_port);
    }
    XLOGI("[+] Start Transmit (%s:%d <-> %s:%d) ......\r\n\n", host1, port1, host2, port2);
	
    maxfd=max(fd1,fd2)+1;
    memset(read_in1,0,MAXSIZE);
    memset(read_in2,0,MAXSIZE);
    memset(send_out1,0,MAXSIZE);
    memset(send_out2,0,MAXSIZE);
	
    timeset.tv_sec=TIMEOUT;	// 超时设定
    timeset.tv_usec=0;
    while(1)
    {
        FD_ZERO(&readfd);
        FD_ZERO(&writefd); 
		
        FD_SET((UINT)fd1, &readfd);
        FD_SET((UINT)fd1, &writefd);
        FD_SET((UINT)fd2, &writefd);
        FD_SET((UINT)fd2, &readfd);
		
        result=select(maxfd,&readfd,&writefd,NULL,&timeset);
        if((result<0) && (errno!=EINTR))
        {
#ifdef WIN32
			XLOGI("[-] Select error:%d.\r\n", WSAGetLastError());
#else
			XLOGI("[-] Select error\r\n");
#endif
            break;
        }
        else if(result==0)
        {
            XLOGI("[-] Socket time out.\r\n");
            break;
        }
        
        if(FD_ISSET(fd1, &readfd))
        {
            /* must < MAXSIZE-totalread1, otherwise send_out1 will flow */
            if(totalread1<MAXSIZE)
			{
                read1=recv(fd1, read_in1, MAXSIZE-totalread1, 0); 
                if((read1==SOCKET_ERROR) || (read1==0))
				//if (read1==SOCKET_ERROR)
				{
#ifdef _WIN32
					XLOGI("[-] Read fd1 data(%d bytes) error:%d,maybe close?\r\n", read1, WSAGetLastError());
#else
					XLOGI("[-] Read fd1 data(%d bytes) error,maybe close?\r\n", read1);
#endif
					break;
				}
				
                memcpy(send_out1+totalread1,read_in1,read1);
                sprintf(tmpbuf,"\r\nRecv %5d bytes from %s:%d\r\n", read1, host1, port1);
                XLOGI(" Recv %5d bytes %16s:%d\r\n", read1, host1, port1);
				
                totalread1+=read1;
                memset(read_in1,0,MAXSIZE);
            }
        }
        if(FD_ISSET(fd2, &writefd))
        {
            int err=0;
            sendcount1=0;
            while(totalread1>0)
            {
                send1=send(fd2, send_out1+sendcount1, totalread1, 0);
                if(send1==0)break;
                if((send1<0) && (errno!=EINTR))
                {
#ifdef _WIN32
					XLOGI("[-] Send to fd2 unknow error:%d.\r\n", WSAGetLastError());
#else
					XLOGI("[-] Send to fd2 unknow error.\r\n");
#endif
                    err=1;
                    break;
                }
                
                if((send1<0) && (errno==ENOSPC)) break;
                sendcount1+=send1;
                totalread1-=send1; 
                XLOGI(" Send %5d bytes %16s:%d\r\n", send1, host2, port2);
            }
			
            if(err==1) break;
            if((totalread1>0) && (sendcount1>0))
            {
                /* move not sended data to start addr */
                memcpy(send_out1,send_out1+sendcount1,totalread1);
                memset(send_out1+totalread1,0,MAXSIZE-totalread1);
            }
            else
				memset(send_out1,0,MAXSIZE);
        } 
        
        if(FD_ISSET(fd2, &readfd))
        {
            if(totalread2<MAXSIZE)
            {
                read2=recv(fd2,read_in2,MAXSIZE-totalread2, 0); 
                if(read2==0)break;
                if((read2<0) && (errno!=EINTR))
                {
#ifdef _WIN32
					XLOGI("[-] Read fd2 data(%d bytes) error:%d,maybe close?\r\n\r\n", read2, WSAGetLastError());
#else
					XLOGI("[-] Read fd2 data(%d bytes) error,maybe close?\r\n\r\n", read2);
#endif
                    break;
                }
                memcpy(send_out2+totalread2,read_in2,read2);
                sprintf(tmpbuf, "\r\nRecv %5d bytes from %s:%d\r\n", read2, host2, port2);
                XLOGI(" Recv %5d bytes %16s:%d\r\n", read2, host2, port2);
				
				totalread2+=read2;
				memset(read_in2,0,MAXSIZE);
            }
		}
        if(FD_ISSET(fd1, &writefd))
        {
            int err2=0;
			sendcount2=0;
			while(totalread2>0)
			{
				send2=send(fd1, send_out2+sendcount2, totalread2, 0);
				if(send2==0)break;
				if((send2<0) && (errno!=EINTR))
				{
#ifdef _WIN32
					XLOGI("[-] Send to fd1 unknow error:%d.\r\n", WSAGetLastError());
#else
					XLOGI("[-] Send to fd1 unknow error.\r\n");
#endif
                    err2=1;
					break;
				}
				if((send2<0) && (errno==ENOSPC)) break;
				sendcount2+=send2;
				totalread2-=send2; 
                
                XLOGI(" Send %5d bytes %16s:%d\r\n", send2, host1, port1);
			}
            if(err2==1) break;
			if((totalread2>0) && (sendcount2 > 0))
            {
                /* move not sended data to start addr */
                memcpy(send_out2, send_out2+sendcount2, totalread2);
                memset(send_out2+totalread2, 0, MAXSIZE-totalread2);
            }
            else
                memset(send_out2,0,MAXSIZE);
        } 
        Sleep(5);
    }/* end while */
	
    closesocket(fd1);
	DeleteSockFromXList((int)fd1);
    closesocket(fd2);
	DeleteSockFromXList((int)fd2);
	
    
    XLOGI("\r\n[+] OK! I Closed The Two Socket.\r\n");  
}
