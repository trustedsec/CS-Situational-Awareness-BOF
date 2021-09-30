#include <windows.h>
#include <iphlpapi.h>
#include "bofdefs.h"
#include "base.c"

#ifdef BOF
//DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetIpNetTable(PMIB_IPNETTABLE IpNetTable,PULONG SizePointer, BOOL Order);

void print_ip_from_int(unsigned int addr)
{
        unsigned char p1, p2, p3, p4;
		char ipStr[20] = {0};

        p1 = (addr & 0x000000FF);
        p2 = (addr & 0x0000FF00) >> 8;
        p3 = (addr & 0x00FF0000) >> 16;
        p4 = (addr & 0xFF000000) >> 24;

		MSVCRT$sprintf(ipStr,"%d.%d.%d.%d", p1,p2,p3,p4);
		internal_printf("%-24s", ipStr);
}

void print_MAC_from_bytes(DWORD length, BYTE* physaddr)
{
	char macStr[24] = {0};
	if(length != 6)
	{
		internal_printf("%-24s", "INVALID MAC LENGTH");
		return;
	}
	MSVCRT$sprintf(macStr, "%02X-%02X-%02X-%02X-%02X-%02X",physaddr[0],physaddr[1],physaddr[2],physaddr[3],physaddr[4],physaddr[5]);
	internal_printf("%-24s",macStr);
}


char* int_to_arp_type(DWORD arp_type)
{
	if(arp_type == 1)
	{
		return "other";
	}else if(arp_type == 2)
	{
		return "invalid";
	}else if(arp_type == 3)
	{
		return "dynamic";
	}else if(arp_type == 4)
	{
		return "static";
	}else
	{
		return "unknown";
	}

}


void arp()
{
	ULONG ret;
	MIB_IPNETTABLE *ipNetTableInfo = NULL;
	MIB_IPNETROW *row;
	ULONG ipNetTableBufLen = 0;
	DWORD p = 0;
	DWORD last_if_index = 0;
	IPHLPAPI$GetIpNetTable(NULL, &ipNetTableBufLen, TRUE);
	ipNetTableInfo = intAlloc(ipNetTableBufLen);
	if (NULL == ipNetTableInfo)
	{
		BeaconPrintf(CALLBACK_ERROR, "Could not alloc memory for ipNetTableInfo");
		goto END;
	}
	ret = IPHLPAPI$GetIpNetTable(ipNetTableInfo, &ipNetTableBufLen, TRUE);
	if ((ret != NO_ERROR) && (ret != ERROR_NO_DATA))
	{
		BeaconPrintf(CALLBACK_ERROR, "Error code: %d", ret);
		BeaconPrintf(CALLBACK_ERROR, "Could not get ipnet table info");
		goto END;
	}	
	row = ipNetTableInfo->table;
	for (p=0; p < ipNetTableInfo->dwNumEntries; p++)
	{
		if (last_if_index != row->dwIndex)
		{
			last_if_index = row->dwIndex;
			internal_printf("\nInteface  --- 0x%X\n",row->dwIndex);
			internal_printf("%-24s%-24s%-24s\n","Internet Address","Physical Address", "Type");
		}
		
		print_ip_from_int(row->dwAddr);

		if (row->dwPhysAddrLen > 0)
		{
			print_MAC_from_bytes(row->dwPhysAddrLen,row->bPhysAddr);
		}
		else
		{
			internal_printf("%-24s","");
		}

		internal_printf("%-24s\n",int_to_arp_type(row->dwType));
		row++;
	}


	END:
		if(ipNetTableInfo){ intFree(ipNetTableInfo);}	
}

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	if(!bofstart())
	{
		return;
	}
	arp();
	printoutput(TRUE);
};

#else

int main()
{
//code for standalone exe for scanbuild / leak checks
}

#endif
