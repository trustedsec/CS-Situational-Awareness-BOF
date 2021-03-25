#include <windows.h>
#include <iphlpapi.h>
#include "bofdefs.h"
#include "base.c"

#ifdef BOF
//DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetIpNetTable(PMIB_IPNETTABLE IpNetTable,PULONG SizePointer, BOOL Order);

char* print_ip_from_int(unsigned int addr)
{
        unsigned char p1, p2, p3, p4;
		char *ipStr = (char*)intAlloc(20 * sizeof(char));

        p1 = (addr & 0x000000FF);
        p2 = (addr & 0x0000FF00) >> 8;
        p3 = (addr & 0x00FF0000) >> 24;
        p4 = (addr & 0xFF000000) >> 24;

		MSVCRT$sprintf(ipStr,"%d.%d.%d.%d", p1,p2,p3,p4);
        return ipStr;
}

char* print_MAC_from_bytes(DWORD length, BYTE* physaddr)
{
	char *macStr = (char*)intAlloc(20 * sizeof(char));
	for (int ii = 0; ii < length; ii++)
	{
		MSVCRT$sprintf(macStr+strlen(macStr),"%02X",physaddr[ii]);
		if (ii < length-1) 
		{
			MSVCRT$sprintf(macStr+strlen(macStr),"%s","-");
		}
		
	}
	return macStr;
}


char* int_to_arp_type(DWORD arp_type)
{
	switch(arp_type)
	{
		case 1:
			return "other";
		case 2:
			return "invalid";
		case 3:
			return "dynamic";
		case 4:
			return "static";
		default:
			return "unknown";

	}
}


void arp()
{
	ULONG ret;
	MIB_IPNETTABLE *ipNetTableInfo = intAlloc(sizeof(PMIB_IPNETTABLE) * 32);
	MIB_IPNETROW *row;
	ULONG ipNetTableBufLen = sizeof(PMIB_IPNETTABLE) * 32;
	DWORD p = 0;
	DWORD last_if_index = 0;

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
		
		internal_printf("%-24s",print_ip_from_int(row->dwAddr));

		if (row->dwPhysAddrLen > 0)
		{
			internal_printf("%-24s",print_MAC_from_bytes(row->dwPhysAddrLen,row->bPhysAddr));
		}
		else
			internal_printf("%-24s","");

		internal_printf("%-24s\n",int_to_arp_type(row->dwType));
		row++;
	}

	END:
		p=0;	
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
