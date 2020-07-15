#include <windows.h>
#include <windns.h>
#include "bofdefs.h"
#include "base.c"

typedef PCWSTR (*myInetNtopW)(
  INT        Family,
  const VOID *pAddr,
  PWSTR      pStringBuf,
  size_t     StringBufSize
);

typedef struct _DNS_CACHE_ENTRY {
    struct _DNS_CACHE_ENTRY* pNext; // Pointer to next entry
    PWSTR pszName; // DNS Record Name
    unsigned short wType; // DNS Record Type
    unsigned short wDataLength; // Not referenced
    unsigned long dwFlags; // DNS Record Flags
} DNSCACHEENTRY, *PDNSCACHEENTRY;

typedef int(WINAPI *DNS_GET_CACHE_DATA_TABLE)(PDNSCACHEENTRY * asdf);
typedef void (WINAPI *P_DnsFree)(PVOID pData, DNS_FREE_TYPE type);

void query_domain(const char * domainname, unsigned short wType, const char * dnsserver)
{
    PDNS_RECORD pdns = NULL;
    DWORD options = 0; //0 also just happends to be DNS_QUERY_STANDARD which is what we want for this
    DWORD status = 0;
    struct in_addr inaddr;
    PIP4_ARRAY pSrvList = NULL;
    unsigned int i = 0;
    LPSTR errormsg = NULL;
    DNS_FREE_TYPE freetype;
    HMODULE WS = LoadLibraryA("WS2_32");
    myInetNtopW inetntow;
    int (*intinet_pton)(INT, LPCSTR, PVOID);
    if(WS == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to load ws2 lib");
        return;
    }
    else
    {
        inetntow = (myInetNtopW)GetProcAddress(WS, "InetNtopW");
        intinet_pton = (int (*)(INT,LPCSTR,PVOID))GetProcAddress(WS, "inet_pton");
        if(!inetntow || !intinet_pton)
        {
            BeaconPrintf(CALLBACK_ERROR, "Could not load functions");
            goto END;
        }
    }
    
    freetype = DnsFreeRecordListDeep; //since when was a define not good enough for microsoft
    if(dnsserver != NULL) // I am assuming dnsserver is never set with cacheOnly
    {
        pSrvList = (PIP4_ARRAY)KERNEL32$LocalAlloc(LPTR, sizeof(IP4_ARRAY));
        if (!pSrvList)
        {
            BeaconPrintf(CALLBACK_ERROR, "could not allocate memory");      
            goto END;
        }
        if(intinet_pton(AF_INET, dnsserver, &(pSrvList->AddrArray[0])) != 1)
        {
            BeaconPrintf(CALLBACK_ERROR, "Could not convert dnsserver from ip to binary");
            KERNEL32$LocalFree(pSrvList);
            goto END;
        }
    //   pSrvList->AddrArray[0] = WSOCK32$inet_addr(dnsserver); //DNS (ASCII) to  IP address
    //   pSrvList->
        pSrvList->AddrCount = 1; 
        options = DNS_QUERY_WIRE_ONLY;
    }
    status = DNSAPI$DnsQuery_A(domainname, wType, options, pSrvList, &pdns, NULL);
    if(pSrvList != NULL)
        KERNEL32$LocalFree(pSrvList);
    if(status != 0 || pdns == NULL)
    {
		internal_printf("Query for domain name failed\n");
		status = Kernel32$FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			status,
			0,
			(LPSTR)&errormsg,
			0,
			NULL
		);
		if(status ==0)
			internal_printf("unable to convert error message\n");
		else
		{
			internal_printf(errormsg);
			KERNEL32$LocalFree(errormsg);
		}
        goto END;
    }


    //this logic was modified from https://www.codeproject.com/Articles/21246/DNS-Query-MFC-based-Application DnsView.cpp
    do {
            wchar_t addr[255] = {0};
                        if(pdns->wType == DNS_TYPE_A)
            {
            inaddr.S_un.S_addr = pdns->Data.A.IpAddress;
            if(inetntow(AF_INET, (LPVOID) &inaddr, addr, 254) == NULL)
            {
                    BeaconPrintf(CALLBACK_ERROR, "bad convert");
                    goto END;
            }
            internal_printf("A %s [%S]\n", pdns->pName, addr);
            }else if(pdns->wType == DNS_TYPE_NS){
                    internal_printf("NS %s %s\n", pdns->pName, pdns->Data.NS.pNameHost);
            }else if(pdns->wType == DNS_TYPE_MD){
                    internal_printf("MD %s %s\n", pdns->pName, pdns->Data.MD.pNameHost);
            }else if(pdns->wType == DNS_TYPE_MF){

                    internal_printf("MF %s %s\n", pdns->pName, pdns->Data.MF.pNameHost);
            }else if(pdns->wType == DNS_TYPE_CNAME){
                    internal_printf("CNAME %s %s\n", pdns->pName, pdns->Data.CNAME.pNameHost);
            }else if(pdns->wType == DNS_TYPE_SOA){

                    internal_printf("SOA %s  nameserv: %s\r\n", pdns->pName, pdns->Data.SOA.pNamePrimaryServer);
                    internal_printf("     admin: %s\r\n", pdns->Data.SOA.pNameAdministrator);
                    internal_printf("    serial: %u\r\n", pdns->Data.SOA.dwSerialNo);
                    internal_printf("   refresh: %u\r\n", pdns->Data.SOA.dwRefresh);
                    internal_printf("       ttl: %u\r\n", pdns->Data.SOA.dwDefaultTtl);
                    internal_printf("    expire: %u\r\n", pdns->Data.SOA.dwExpire);
                    internal_printf("     retry: %u", pdns->Data.SOA.dwRetry);
            }else if(pdns->wType == DNS_TYPE_MB){
                    internal_printf("MB %s %s\n", pdns->pName, pdns->Data.MB.pNameHost);
            }else if(pdns->wType == DNS_TYPE_MG){
                    internal_printf("MG %s %s\n", pdns->pName, pdns->Data.MG.pNameHost);
            }else if(pdns->wType == DNS_TYPE_MR){

                    internal_printf("MR %s %s\n", pdns->pName, pdns->Data.MR.pNameHost);
            }else if(pdns->wType == DNS_TYPE_WKS){

                    inaddr.S_un.S_addr = pdns->Data.WKS.IpAddress;
                    //internal_printf("WKS %s [%s] proto: %d mask: %d\n", pdns->pName, WS2_32$inet_ntoa(inaddr), pdns->Data.WKS.chProtocol, pdns->Data.WKS.BitMask);
            }else if(pdns->wType == DNS_TYPE_PTR){

                    internal_printf("PTR %s %s\n", pdns->pName, pdns->Data.PTR.pNameHost);
            }else if(pdns->wType == DNS_TYPE_HINFO){

                    internal_printf("HINFO %s\n", pdns->pName);
                    for (i = 0; i < pdns->Data.HINFO.dwStringCount; i++) {
                            internal_printf("%s\n", pdns->Data.HINFO.pStringArray[i]);
                    }
            }else if(pdns->wType == DNS_TYPE_MINFO){
                    internal_printf("MINFO %s err: %s name: %s\n", pdns->pName, pdns->Data.MINFO.pNameErrorsMailbox, pdns->Data.MINFO.pNameMailbox);
            }else if(pdns->wType == DNS_TYPE_MX){

                    internal_printf("MX %s %s pref: %d\n", pdns->pName, pdns->Data.MX.pNameExchange, pdns->Data.MX.wPreference);
            }else if(pdns->wType == DNS_TYPE_TEXT){

                    internal_printf("TEXT %s\n", pdns->pName);
                    for (i = 0; i < pdns->Data.TXT.dwStringCount; i++) {
                            internal_printf("%s\n", pdns->Data.TXT.pStringArray[i]);
                    }
            }else if(pdns->wType ==DNS_TYPE_RP){

                    internal_printf("RP %s err: %s name: %s\n", pdns->pName, pdns->Data.RP.pNameErrorsMailbox, pdns->Data.RP.pNameMailbox);
            }else if(pdns->wType == DNS_TYPE_AFSDB){

                    internal_printf("AFSDB %s %s pref: %d\n", pdns->pName, pdns->Data.AFSDB.pNameExchange, pdns->Data.AFSDB.wPreference);
            }else if(pdns->wType == DNS_TYPE_X25){

                    internal_printf("X25 %s\n", pdns->pName);
                    for (i = 0; i < pdns->Data.X25.dwStringCount; i++) {
                            internal_printf("%s\n", pdns->Data.X25.pStringArray[i]);
                    }
            }else if(pdns->wType == DNS_TYPE_ISDN){

                    internal_printf("ISDN %s\n", pdns->pName);
                    for (i = 0; i < pdns->Data.ISDN.dwStringCount; i++) {
                            internal_printf("%s\n", pdns->Data.ISDN.pStringArray[i]);
                    }
            }else if(pdns->wType == DNS_TYPE_RT){

                    internal_printf("RT %s %s pref: %d\n", pdns->pName, pdns->Data.RT.pNameExchange, pdns->Data.RT.wPreference);
            }else if(pdns->wType == DNS_TYPE_AAAA){

                    internal_printf("AAAA %s %s pref: %d [", pdns->pName);
                    for (i = 0; i < 16; i++) {
                            internal_printf("%d", pdns->Data.AAAA.Ip6Address.IP6Byte[i]);
                            if (i != 15)
                                    internal_printf(".");
                    }
                    internal_printf("]");
            }else if(pdns->wType == DNS_TYPE_SRV){

                    internal_printf("SRV %s %s port:%d prior:%d weight:%d\n", pdns->pName, pdns->Data.SRV.pNameTarget, pdns->Data.SRV.wPort, pdns->Data.SRV.wPriority, pdns->Data.SRV.wWeight);
            }else if(pdns->wType == DNS_TYPE_WINSR){

                    internal_printf("NBSTAT %s %s\n", pdns->pName, pdns->Data.WINSR.pNameResultDomain);
            }else if(pdns->wType == DNS_TYPE_KEY){

                    internal_printf("DNSKEY %s: flags %d, Protocol %d, Algorithm %d\n", pdns->pName, pdns->Data.KEY.wFlags, pdns->Data.KEY.chProtocol, pdns->Data.KEY.chAlgorithm);
            }else{

                    internal_printf("nope", pdns->pName, pdns->wType);
            }    

        pdns = pdns->pNext;
    } while (pdns);
    //DnsRecordListFree(pdns, freetype);
    DNSAPI$DnsFree(pdns, freetype);
    END:
    FreeLibrary(WS);

}

int ListDnsCache(void){
    char* dnsValue = NULL;
    int retcode = 0;
    PDNSCACHEENTRY pEntry = NULL, pHead = NULL, pPrev = NULL;
    HINSTANCE hLib = LoadLibrary("DNSAPI.dll");
    if (hLib == NULL){
        BeaconPrintf(CALLBACK_ERROR, "Failed to load dnsapi: %p\n", hLib);
        retcode = -1;
        goto CLEANUP;
    }
    // Get function address
    DNS_GET_CACHE_DATA_TABLE DnsGetCacheDataTable =
        (DNS_GET_CACHE_DATA_TABLE)GetProcAddress(hLib, "DnsGetCacheDataTable");
    P_DnsFree pDnsFree = (P_DnsFree)GetProcAddress(hLib, "DnsFree");
    if (DnsGetCacheDataTable == NULL){
        BeaconPrintf(CALLBACK_ERROR, "Failed to load DnsGetCache: %p\n", DnsGetCacheDataTable);
        retcode = -1;
        goto CLEANUP;
    }
    int stat = DnsGetCacheDataTable(&pEntry); //allocates memory into pEntry
    //internal_printf("stat = %d\n", stat);
    pHead = pEntry;
    if(pEntry == NULL || pEntry->pNext == NULL)
    {
        internal_printf("No results found\n");
        retcode = -1;
        goto CLEANUP;
    }
    pEntry = pEntry->pNext;
    while(pEntry) {
		dnsValue = Utf16ToUtf8((pEntry->pszName));
        //internal_printf("Entry: %s\nType: %d\n", dnsValue, (pEntry->wType));
        internal_printf("Cache record: %s   | TYPE %d\n", dnsValue, pEntry->wType);
        query_domain(dnsValue, pEntry->wType, NULL);
        if (dnsValue){
            intFree(dnsValue);
            dnsValue = NULL;
        }
        pPrev = pEntry;
        pEntry = pEntry->pNext;
        //pDnsApiFree(pPrev);
        pDnsFree(pPrev, DnsFreeFlat);
    }

CLEANUP:
    if (pHead){
        //pDnsApiFree(pHead);
        pDnsFree(pHead, DnsFreeFlat);
        pEntry = NULL;
    }
    if(hLib)
        FreeLibrary(hLib);
    return retcode;
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
	ListDnsCache();
	printoutput(TRUE);
	bofstop();
};
