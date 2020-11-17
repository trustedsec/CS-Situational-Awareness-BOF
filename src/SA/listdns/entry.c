#include <windows.h>
#include <windns.h>
#include "bofdefs.h"
#include "base.c"

typedef struct _DNS_CACHE_ENTRY {
    struct _DNS_CACHE_ENTRY* pNext; // Pointer to next entry
    PWSTR pszName; // DNS Record Name
    unsigned short wType; // DNS Record Type
    unsigned short wDataLength; // Not referenced
    unsigned long dwFlags; // DNS Record Flags
} DNSCACHEENTRY, *PDNSCACHEENTRY;

int ListDnsCache(){
    char* dnsValue = NULL;
    int retcode = 0;
    PDNSCACHEENTRY pEntry = NULL, pHead = NULL, pPrev = NULL;
    DNSAPI$DnsGetCacheDataTable(&pEntry); //allocates memory into pEntry
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
        internal_printf("Cache record: %s   | TYPE %d\n", dnsValue, pEntry->wType);
        if (dnsValue){
            intFree(dnsValue);
            dnsValue = NULL;
        }
        pPrev = pEntry;
        pEntry = pEntry->pNext;
        DNSAPI$DnsFree(pPrev, DnsFreeFlat);
    }

CLEANUP:
    if (pHead){
        DNSAPI$DnsFree(pHead, DnsFreeFlat);
        pEntry = NULL;
    }
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
};



