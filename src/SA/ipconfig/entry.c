
#include <windows.h>
#include <iphlpapi.h>
#include "bofdefs.h"
#include "base.c"

typedef  DWORD (*getadaptinfo)(LPVOID, PULONG);
typedef DWORD (*getnetparms)(LPVOID, PULONG);

void getIPInfo(){
    IP_ADAPTER_INFO * info = intAlloc(sizeof(IP_ADAPTER_INFO) * 32); // have to keep stack < 4K
    PIP_ADAPTER_INFO p = NULL;
    PFIXED_INFO pFixedInfo = NULL;
    PIP_ADDR_STRING pIPAddr;
    ULONG netOutBufLen = 0;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO) * 32;
    DWORD ret;
    int i = 0;


    ret = IPHLPAPI$GetAdaptersInfo(info, &ulOutBufLen);
    if (ret != ERROR_SUCCESS) {
		BeaconPrintf(CALLBACK_ERROR, "could not get network adapter info");
        goto END;
    }
    if(IPHLPAPI$GetNetworkParams(pFixedInfo, &netOutBufLen) == ERROR_BUFFER_OVERFLOW){
        pFixedInfo = (FIXED_INFO *)intAlloc(netOutBufLen);
        if (pFixedInfo == NULL)
        {

			BeaconPrintf(CALLBACK_ERROR, "could not get network adapter info");
            goto END;
        }
        if (IPHLPAPI$GetNetworkParams(pFixedInfo, &netOutBufLen) != NO_ERROR)
        {
			BeaconPrintf(CALLBACK_ERROR, "could not get network adapter info");
            goto END;
        }

    }
	else
	{
		BeaconPrintf(CALLBACK_ERROR, "could not get network adapter info");
		goto END;
	}
    for (p = info; p; p = p->Next) {
			internal_printf( "%s\n", p->AdapterName);
			switch(p->Type){
			case MIB_IF_TYPE_ETHERNET:
				internal_printf(  "%s", "\tEthernet\n");
				break;
			default:
				internal_printf(  "%s", "\tUnknownType\n");
				break;
			}
			internal_printf(  "\t%s\n", p->Description);
			internal_printf(  "\t");
			for (i = 0; i < p->AddressLength; i++) {
				if (i == (p->AddressLength - 1)){
					internal_printf(  "%.2X\n", (int) p->Address[i]);
				}
				else{
					internal_printf(  "%.2X-", (int) p->Address[i]);
				}
			}
			internal_printf(  "\t%s\n", p->IpAddressList.IpAddress.String);
			
	}
	internal_printf(  "Hostname: \t%s\n", pFixedInfo->HostName);
	internal_printf(  "DNS Suffix: \t%s\n", pFixedInfo->DomainName);
	internal_printf(  "DNS Server: \t%s\n", pFixedInfo->DnsServerList.IpAddress.String);
	pIPAddr = pFixedInfo->DnsServerList.Next;
	while (pIPAddr){
		internal_printf(  "\t\t%s\n", pIPAddr->IpAddress.String);
		pIPAddr = pIPAddr->Next;
	}
	END:
    if (pFixedInfo){
        intFree(pFixedInfo);
        pFixedInfo = NULL;
    }
	if(info){
		intFree(info);
		info = NULL;
	}
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
	getIPInfo();
	printoutput(TRUE);
};

#else
int main()
{
	getIPInfo();
}

#endif
