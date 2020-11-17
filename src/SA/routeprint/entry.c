/*
#define REACTOS_STR_FILE_DESCRIPTION   "ReactOS TCP/IPv4 Win32 Route"
#define REACTOS_STR_INTERNAL_NAME      "route"
#define REACTOS_STR_ORIGINAL_FILENAME  "route.exe"
#define REACTOS_STR_ORIGINAL_COPYRIGHT "Art Yerkes (arty@users.sourceforge.net)"
modified from base/applications/network/route/route.c
*/
#include <windows.h>
#include <iphlpapi.h>
#include "bofdefs.h"
#include "base.c"
#define IPBUF 17
#define IN_ADDR_OF(x) *((struct in_addr *)&(x))

int PrintRoutes()
{
    PMIB_IPFORWARDTABLE IpForwardTable = NULL;
    PIP_ADAPTER_INFO pAdapterInfo = NULL, curAdapter = NULL;
    ULONG Size = 0;
    DWORD Error = 0;
    ULONG adaptOutBufLen = 0;
    CHAR DefGate[16];
    CHAR Destination[IPBUF], Gateway[IPBUF], Netmask[IPBUF];
    unsigned int i;

    /* set required buffer size */

    if (IPHLPAPI$GetAdaptersInfo( NULL, &adaptOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
       pAdapterInfo = (IP_ADAPTER_INFO *) intAlloc (adaptOutBufLen);
       if (pAdapterInfo == NULL)
       {
           Error = ERROR_NOT_ENOUGH_MEMORY;
           goto Error;
       }
    }

    if( (IPHLPAPI$GetIpForwardTable( NULL, &Size, TRUE )) == ERROR_INSUFFICIENT_BUFFER )
    {
        if (!(IpForwardTable = intAlloc( Size )))
        {
            Error = ERROR_NOT_ENOUGH_MEMORY;
            goto Error;
        }
    }else
    {
        Error = KERNEL32$GetLastError();
        goto Error;
    }
    

    if (((Error = IPHLPAPI$GetAdaptersInfo(pAdapterInfo, &adaptOutBufLen)) == NO_ERROR) &&
        ((Error = IPHLPAPI$GetIpForwardTable(IpForwardTable, &Size, TRUE)) == NO_ERROR))
    {
        MSVCRT$sprintf(DefGate,
                  "%s",
                  pAdapterInfo->GatewayList.IpAddress.String);
       internal_printf("===========================================================================\n");
       internal_printf("Interface List\n");
        /* FIXME - sort by the index! */
        curAdapter = pAdapterInfo;
        while (curAdapter)
        {
           internal_printf("0x%lu ........................... %s\n",
                     curAdapter->Index, curAdapter->Description);
            curAdapter = curAdapter->Next;
        }
       internal_printf("===========================================================================\n");

       internal_printf("===========================================================================\n");
       internal_printf("Active Routes:\n");
       internal_printf( "%-27s%-17s%-14s%-11s%-10s\n",
                  "Network Destination",
                  "Netmask",
                  "Gateway",
                  "Interface",
                  "Metric" );
        for( i = 0; i < IpForwardTable->dwNumEntries; i++ )
        {
            MSVCRT$sprintf( Destination,
                       "%s",
                       WS2_32$inet_ntoa( IN_ADDR_OF(IpForwardTable->table[i].dwForwardDest) ) );
            MSVCRT$sprintf( Netmask,
                       "%s",
                       WS2_32$inet_ntoa( IN_ADDR_OF(IpForwardTable->table[i].dwForwardMask) ) );
            MSVCRT$sprintf( Gateway,
                       "%s",
                       WS2_32$inet_ntoa( IN_ADDR_OF(IpForwardTable->table[i].dwForwardNextHop) ) );

           internal_printf("%17s%17s%17s%16ld%9ld\n",
                      Destination,
                      Netmask,
                      Gateway,
                      IpForwardTable->table[i].dwForwardIfIndex,
                      IpForwardTable->table[i].dwForwardMetric1 );
            
        }
		internal_printf("Default Gateway:%18s\n", DefGate);
		internal_printf("===========================================================================\n");
		internal_printf("Persistent Routes:\n");
        intFree(IpForwardTable);
        intFree(pAdapterInfo);
        return ERROR_SUCCESS;
    }
    else
    {
Error:
        if (pAdapterInfo) intFree(pAdapterInfo);
        if (IpForwardTable) intFree(IpForwardTable);
        return Error;
    }
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
	PrintRoutes();
	printoutput(TRUE);
};

#else
int main()
{
    PrintRoutes();
}

#endif
