/*
2  * PROJECT:     ReactOS netstat utility
3  * LICENSE:     GPL - See COPYING in the top level directory
4  * FILE:        base/applications/network/netstat/netstat.c
5  * PURPOSE:     display IP stack statistics
6  * COPYRIGHT:   Copyright 2005 Ged Murphy <gedmurphy@gmail.com>
7  */

#include <windows.h>
#include <winbase.h>
#include <iphlpapi.h>
#include "bofdefs.h"
#include "base.c"

WINBASEAPI DWORD WINAPI IPHLPAPI$GetExtendedTcpTable(PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved);
WINBASEAPI DWORD WINAPI IPHLPAPI$GetExtendedUdpTable(PVOID pUdpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, UDP_TABLE_CLASS TableClass, ULONG Reserved);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$QueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize);

#define HOSTNAMELEN 256
#define PORTNAMELEN 256
#define ADDRESSLEN 512

CHAR TcpState[][32] = {
    "???",
    "CLOSED",
    "LISTENING",
    "SYN_SENT",
    "SYN_RCVD",
    "ESTABLISHED",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
    "DELETE_TCB"
};

char* GetIpHostName(BOOL Local, UINT IpAddr, CHAR Name[], int NameLen)
{
//  struct hostent *phostent;
    UINT nIpAddr;

    /* display dotted decimal */
    nIpAddr = WS2_32$htonl(IpAddr);
    MSVCRT$sprintf(Name, "%u.%u.%u.%u",
            (nIpAddr >> 24) & 0xFF,
            (nIpAddr >> 16) & 0xFF,
            (nIpAddr >> 8) & 0xFF,
            (nIpAddr) & 0xFF);
   return Name;
}

char* GetPortName(UINT Port, PCSTR Proto, CHAR Name[], INT NameLen)
{
    MSVCRT$sprintf(Name, "%u", WS2_32$htons((WORD)Port));
    return Name;
}

void GetNameByPID(DWORD processId, char* procName, DWORD *procNameLength) {

HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, processId);
BOOL state;

	if (NULL != hProcess )
    	{
		state = KERNEL32$QueryFullProcessImageNameA(hProcess, 0, (LPSTR)procName, procNameLength);
		KERNEL32$CloseHandle( hProcess );
		if(state == TRUE) {
		    return;
		} else {
		    procName = "PERM\x00";
		    procNameLength = 0;
		    BeaconPrintf(CALLBACK_ERROR, "Failed to determine processName by PID %lu QueryFullProcessImageNameA failed", processId);
		}
    	} else {
		procName = "PERM\x00";
		procNameLength = 0;
	}
	return;
}

VOID ShowUdpTable()
{
//    PMIB_UDPTABLE udpTable;
    PMIB_UDPTABLE_OWNER_PID uTable;
    DWORD error, dwSize;
    DWORD i;
    CHAR HostIp[HOSTNAMELEN], HostPort[PORTNAMELEN];
    CHAR Host[ADDRESSLEN];

    /* Get the table of UDP endpoints */
    dwSize = 0;
    error = IPHLPAPI$GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (error != ERROR_INSUFFICIENT_BUFFER)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to snapshot UDP endpoints.\n");
        return;
    }
    uTable = (PMIB_UDPTABLE_OWNER_PID) intAlloc(dwSize);
    error = IPHLPAPI$GetExtendedUdpTable(uTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (error)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to snapshot UDP endpoints table.\n");
        intFree(uTable);
        return;
    }

    /* Dump the UDP table */

    for (i = 0; i < uTable->dwNumEntries; i++)
    {
	MIB_UDPROW_OWNER_PID row = uTable->table[i];
        /* I've split this up so it's easier to follow */
        GetIpHostName(TRUE, row.dwLocalAddr, HostIp, HOSTNAMELEN);
        GetPortName(row.dwLocalPort, "tcp", HostPort, PORTNAMELEN);
        MSVCRT$sprintf(Host, "%s:%s", HostIp, HostPort);
	DWORD pid = row.dwOwningPid;
	char name[MAX_PATH];
	for (int i=0; i<MAX_PATH; i++) { name[i] = '\x00'; }
	DWORD size = MAX_PATH;
	DWORD* sizep = &size;
	GetNameByPID(pid, name, sizep);
	size = (*sizep);
        internal_printf("  %-6s %-22s %-22s %75s (%5i)\n", "UDP", Host,  "*:*", name, pid);
    }

    intFree(uTable);
}


void Netstat(){
//    PMIB_TCPTABLE tcpTable;
    PMIB_TCPTABLE_OWNER_PID ptTable;
    DWORD error, dwSize;
    DWORD i;
    CHAR HostIp[HOSTNAMELEN], HostPort[PORTNAMELEN];
    CHAR RemoteIp[HOSTNAMELEN], RemotePort[PORTNAMELEN];
    CHAR Host[ADDRESSLEN];
    CHAR Remote[ADDRESSLEN];

    dwSize = 0;
    error = IPHLPAPI$GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (error != ERROR_INSUFFICIENT_BUFFER)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to snapshot TCP endpoints.\n");
        return;
    }
	// now that we know the buffer size, alloc it and call again with our struct
    ptTable = (PMIB_TCPTABLE_OWNER_PID) intAlloc(dwSize);
    error = IPHLPAPI$GetExtendedTcpTable(ptTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (error)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to snapshot TCP endpoints table.\n");
        intFree(ptTable);
        return;
    }
    internal_printf("Processing: %ld Entries\n", ptTable->dwNumEntries);
    internal_printf("  %-4s %-22s %-22s %11s %75s %5s\n", "PROTO", "SRC", "DST", "STATE", "PROCESS", "PID");

    for (i = 0; i < ptTable->dwNumEntries; i++)
    {
		MIB_TCPROW_OWNER_PID row = ptTable->table[i];
        /* If we aren't showing all connections, only display established, close wait
 *          * and time wait. This is the default output for netstat */
        if (1 ||(row.dwState ==  MIB_TCP_STATE_ESTAB)
            || (row.dwState ==  MIB_TCP_STATE_CLOSE_WAIT)
            || (row.dwState ==  MIB_TCP_STATE_TIME_WAIT))
        {
            /* I've split this up so it's easier to follow */
           GetIpHostName(TRUE, row.dwLocalAddr, HostIp, HOSTNAMELEN);
           GetPortName(row.dwLocalPort, "tcp", HostPort, PORTNAMELEN);
           MSVCRT$sprintf(Host, "%s:%s", HostIp, HostPort);

           if (row.dwState ==  MIB_TCP_STATE_LISTEN)
           {
               MSVCRT$sprintf(Remote, "LISTEN");
           }
           else
           {
               GetIpHostName(FALSE, row.dwRemoteAddr, RemoteIp, HOSTNAMELEN);
               GetPortName(row.dwRemotePort, "tcp", RemotePort, PORTNAMELEN);
               MSVCRT$sprintf(Remote, "%s:%s", RemoteIp, RemotePort);
           }
	   DWORD pid = row.dwOwningPid;
	   char name[MAX_PATH];
	   for(int i=0; i<MAX_PATH; i++) { name[i] = '\x00'; }
	   DWORD size = MAX_PATH;
	   DWORD* sizep = &size;
	   GetNameByPID(pid, name, sizep);
	   size = (*sizep);
           internal_printf("  %-4s %-22s %-22s %11s %75s (%5i)\n", "TCP", Host, Remote, TcpState[row.dwState], name, pid);
//           internal_printf("  %-6s %-22s %-22s %s\n", "TCP", Host, Remote, TcpState[row.dwState]);
        }
    }
    intFree(ptTable);
    ShowUdpTable();
    return;
}

#ifdef BOF

VOID go(
        IN PCHAR Buffer,
        IN ULONG Length
)
{
        if(!bofstart())
        {
                return;
        }
        Netstat();
        printoutput(TRUE);
};

#else

int main()
{
    Netstat();
}

#endif

