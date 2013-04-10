#include "NetBind.h"
#include "CryptIt.h"
#include "Configure.h"
#include "Xor.h"
#include "LogFilePort.h"
#include <vector>

std::vector<int> g_xSocket;
//std::vector<int> g_nSocket;

extern CONFIGURE_STRUCT g_Configure;

CRITICAL_SECTION g_SockX = {0};
//fp_send g_pMySend = NULL;
//fp_recv g_pMyRecv = NULL;
//fp_connect g_pConnect = NULL;

#ifdef _WIN32
typedef int (__stdcall * fp_send)(IN SOCKET s, const char FAR * buf, IN int len, IN int flags);
typedef int (__stdcall * fp_recv)(IN SOCKET s, char FAR * buf, IN int len, IN int flags);
typedef int (__stdcall * fp_connect)(IN SOCKET s, const struct sockaddr FAR * name, IN int namelen);

DECLARE_DETOURE( fp_send, send );
DECLARE_DETOURE( fp_recv, recv );
DECLARE_DETOURE( fp_connect, connect );
#elif _LINUX

#endif

void SetSockToXList(int s)
{
	XLOGI("Entry SetSockToXList");
	EnterCriticalSection(&g_SockX);
	g_xSocket.push_back(s);
	LeaveCriticalSection(&g_SockX);
	XLOGI("Leave SetSockToXList");
}

void DeleteSockFromXList(int s)
{
	XLOGI("Entry DeleteSockFromXList");

	EnterCriticalSection(&g_SockX);
	for (std::vector<int>::iterator i = g_xSocket.begin(); i < g_xSocket.end(); i++)
	{
		if (s == *i)
		{
			g_xSocket.erase(i);
			LeaveCriticalSection(&g_SockX);
			XLOGI("Erase socket and Leave DeleteSockFromXList");
			return;
		}
	}

	LeaveCriticalSection(&g_SockX);
	XLOGI("Leave SetSockToXList");
}

bool FindXSocket( int s )
{
	EnterCriticalSection(&g_SockX);
	for (std::vector<int>::iterator i = g_xSocket.begin(); i < g_xSocket.end(); i++)
	{
		if (s == *i)
		{
			LeaveCriticalSection(&g_SockX);
			return true;
		}
	}

	LeaveCriticalSection(&g_SockX);
	return false;
}

//////////////////////////////////////////////////////////////////////////
int __stdcall DECLARE_DETOURE_FUN(send)(IN SOCKET s, const char FAR * buf, IN int len, IN int flags)
{
	int ret = 0;
	XLOGI("send to Length:%d bytes -> 0x%4X, password = 0x%4X", len, (int)s, g_Configure.dwCrc32Password);
	if ((g_Configure.bHashX == TRUE) && 
		(g_Configure.bSock5Proxy == FALSE))
	{
		if (FindXSocket((int)s) == TRUE)
		{
			//XLOGI("send crypt data size = %d", len);
			//ret = CALL_ORIGINAL(send)(s, (char *)&len, 4, flags);
			//if (ret <= 0) return ret;

			XLOGI("send crypt data");
			XorArrayForArray(g_Configure.dwCrc32Password, (unsigned char*)buf, (unsigned char*)buf, len);
			ret = CALL_ORIGINAL(send)(s, buf, len, flags);
			return ret;
		}
	}

	// Èç¹û²»¼ÓÃÜÔòÖ±½Ó·¢ËÍ
	ret = CALL_ORIGINAL(send)(s, buf, len, flags);
	return ret;
}

int __stdcall DECLARE_DETOURE_FUN(recv)(IN SOCKET s, char FAR * buf, IN int len, IN int flags)
{
	int ret = 0;
	XLOGI("recv from 0x%4X, password = 0x%4X", (int)s, g_Configure.dwCrc32Password);

	// Èç¹ûÊÇÒª¼ÓÃÜµÄÌ×½Ó×ÖÔòÔÚÕâÀï°ÑËùÓÐ°ü¶¼»º³åÍê±Ï
	if ((g_Configure.bHashX == TRUE) && (
		g_Configure.bSock5Proxy == FALSE))
	{
		// Èç¹û´ËÌ×½Ó×ÖÒª½øÐÐ¼ÓÃÜ
		if (FindXSocket((int)s) == TRUE)
		{
			XLOGI("crypt recv data");

			// Ê×ÏÈ½ÓÊÕ°ü³¤¶È
			//int psize = 0;
			//ret = CALL_ORIGINAL(recv)(s, (char *)&psize, 4, flags);
			//if (ret <= 0) return ret;
			
			//int getsize = 0;
			//char *tmp = (char *)malloc(MAXSIZE);
			// ÔÚÕâÀï»º´æËùÓÐ°ü
			//while (psize > 0)
			//{
			//	ret = CALL_ORIGINAL(recv)(s, tmp+getsize, MAXSIZE-getsize, flags);
			//	if (ret <= 0) {
			//		free(tmp);
			//		return ret;
			//	}
			//	psize -= getsize;
			//}

			// ½øÐÐ¼Ó½âÃÜ
			ret = CALL_ORIGINAL(recv)(s, buf, len, flags);
			XorArrayForArray(g_Configure.dwCrc32Password, (unsigned char*)buf, (unsigned char*)buf, len);
			return ret;
			//free(tmp);
			//return psize;
		}
	}

	// Èç¹û¼ÓÃÜÃ»ÓÐ¿ªÆôµÄ»°
	ret = CALL_ORIGINAL(recv)(s, buf, len, flags);
	return ret;
}

int __stdcall DECLARE_DETOURE_FUN(connect)(IN SOCKET s, const struct sockaddr FAR * name, IN int namelen)
{
	XLOGI("Entry connect");
	int ret = CALL_ORIGINAL(connect)(s, name, namelen);
	XLOGI("Level connect, return value = %d, error = %d", ret, WSAGetLastError());
	return ret;
}

unsigned long GetCurrAddress( void *pAddress )
{
	unsigned long ret = 0;
	unsigned long *pCurr = (unsigned long *)pAddress;
	if (*(char *)pCurr == 0xE9)// Ò»¸öÔ¶Ìø
	{
		
	}

	Return ret;
}

void InstallCrypt()
{
	INSTALL_DETOURE( send );
	INSTALL_DETOURE( recv );
	INSTALL_DETOURE( connect );
}
