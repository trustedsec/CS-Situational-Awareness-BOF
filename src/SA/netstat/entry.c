/*
2  * PROJECT:     ReactOS netstat utility
3  * LICENSE:     GPL - See COPYING in the top level directory
4  * FILE:        base/applications/network/netstat/netstat.c
5  * PURPOSE:     display IP stack statistics
6  * COPYRIGHT:   Copyright 2005 Ged Murphy <gedmurphy@gmail.com>
7  */

#include <windows.h>
#include <iphlpapi.h>
#include "bofdefs.h"
#include "base.c"

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

VOID ShowUdpTable()
{
    PMIB_UDPTABLE udpTable;
    DWORD error, dwSize;
    DWORD i;
    CHAR HostIp[HOSTNAMELEN], HostPort[PORTNAMELEN];
    CHAR Host[ADDRESSLEN];

    /* Get the table of UDP endpoints */
    dwSize = 0;
    error = IPHLPAPI$GetUdpTable(NULL, &dwSize, TRUE);
    if (error != ERROR_INSUFFICIENT_BUFFER)
    {
		BeaconPrintf(CALLBACK_ERROR, "Failed to snapshot UDP endpoints.\n");
        return;
    }
    udpTable = (PMIB_UDPTABLE) intAlloc(dwSize);
    error = IPHLPAPI$GetUdpTable(udpTable, &dwSize, TRUE);
    if (error)
    {
		BeaconPrintf(CALLBACK_ERROR, "Failed to snapshot UDP endpoints table.\n");
        intFree(udpTable);
        return;
    }

    /* Dump the UDP table */

    for (i = 0; i < udpTable->dwNumEntries; i++)
    {

        /* I've split this up so it's easier to follow */
        GetIpHostName(TRUE, udpTable->table[i].dwLocalAddr, HostIp, HOSTNAMELEN);
        GetPortName(udpTable->table[i].dwLocalPort, "tcp", HostPort, PORTNAMELEN);
        MSVCRT$sprintf(Host, "%s:%s", HostIp, HostPort);
        internal_printf("  %-6s %-22s %-22s\n", "UDP", Host,  "*:*");    
    }

    intFree(udpTable);
}

void Netstat(){
    PMIB_TCPTABLE tcpTable;
    DWORD error, dwSize;
    DWORD i;
    CHAR HostIp[HOSTNAMELEN], HostPort[PORTNAMELEN];
    CHAR RemoteIp[HOSTNAMELEN], RemotePort[PORTNAMELEN];
    CHAR Host[ADDRESSLEN];
    CHAR Remote[ADDRESSLEN];

	dwSize = 0;
    error = IPHLPAPI$GetTcpTable(NULL, &dwSize, TRUE);
    if (error != ERROR_INSUFFICIENT_BUFFER)
    {
		BeaconPrintf(CALLBACK_ERROR, "Failed to snapshot TCP endpoints.\n");
        return;
    }
    tcpTable = (PMIB_TCPTABLE) intAlloc(dwSize);
    error = IPHLPAPI$GetTcpTable(tcpTable, &dwSize, TRUE);
    if (error)
    {
		BeaconPrintf(CALLBACK_ERROR, "Failed to snapshot TCP endpoints table.\n");
        intFree(tcpTable);
        return;
    }
	internal_printf("Processing: %ld Entries\n", tcpTable->dwNumEntries);
 
    for (i = 0; i < tcpTable->dwNumEntries; i++)
    {
        /* If we aren't showing all connections, only display established, close wait
 *          * and time wait. This is the default output for netstat */
        if (1 ||(tcpTable->table[i].dwState ==  MIB_TCP_STATE_ESTAB)
            || (tcpTable->table[i].dwState ==  MIB_TCP_STATE_CLOSE_WAIT)
            || (tcpTable->table[i].dwState ==  MIB_TCP_STATE_TIME_WAIT))
        {
            /* I've split this up so it's easier to follow */
            GetIpHostName(TRUE, tcpTable->table[i].dwLocalAddr, HostIp, HOSTNAMELEN);
            GetPortName(tcpTable->table[i].dwLocalPort, "tcp", HostPort, PORTNAMELEN);
            MSVCRT$sprintf(Host, "%s:%s", HostIp, HostPort);

            if (tcpTable->table[i].dwState ==  MIB_TCP_STATE_LISTEN)
            {
                MSVCRT$sprintf(Remote, "LISTEN");
            }
            else
            {
                GetIpHostName(FALSE, tcpTable->table[i].dwRemoteAddr, RemoteIp, HOSTNAMELEN);
                GetPortName(tcpTable->table[i].dwRemotePort, "tcp", RemotePort, PORTNAMELEN);
                MSVCRT$sprintf(Remote, "%s:%s", RemoteIp, RemotePort);
                
            }
           internal_printf("  %-6s %-22s %-22s %s\n", "TCP",
            Host, Remote, TcpState[tcpTable->table[i].dwState]);         
        }
    }
    intFree(tcpTable);
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
