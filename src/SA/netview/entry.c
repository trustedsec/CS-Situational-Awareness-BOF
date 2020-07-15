

/*
 * PROJECT:     ReactOS netstat utility
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        base/applications/network/netstat/netstat.c
 * PURPOSE:     display IP stack statistics
 * COPYRIGHT:   Copyright 2005 Ged Murphy <gedmurphy@gmail.com>
 */

#include <windows.h>
#include <lmserver.h>
#include <lmerr.h>
#include "beacon.h"
#include "bofdefs.h"
#define bufsize 8192
#include "base.c"

void netview_enum(wchar_t* domain)
{
    NET_API_STATUS nStatus;
    LPWSTR pszServerName = NULL;
    DWORD dwLevel = 101;
    LPSERVER_INFO_101 pBuf = NULL;
    LPSERVER_INFO_101 pTmpBuf;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwServerType = SV_TYPE_ALL;
    LPWSTR pszDomainName = domain;
    DWORD dwResumeHandle = 0;
    int i = 0;
   
    nStatus = NETAPI32$NetServerEnum(pszServerName,
                dwLevel,
                (LPBYTE *) & pBuf,
                dwPrefMaxLen,
                &dwEntriesRead,
                &dwTotalEntries,
                dwServerType,
                pszDomainName,
                &dwResumeHandle);
    if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
    {
        if ((pTmpBuf = pBuf) != NULL)
        {
            for (i = 0; i < dwEntriesRead; i++)
            {
                if (pTmpBuf == NULL)
                {
                    BeaconPrintf(CALLBACK_ERROR, "Could not access entry");
                    return;
                }
                else
                {
                    internal_printf("%S\n", pTmpBuf->sv101_name);
                }
            pTmpBuf++;
            }
        }
    } 
    if (pBuf != NULL)
    {
        NETAPI32$NetApiBufferFree(pBuf);
    }
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser;

    wchar_t * domain;
    wchar_t * rdomain = NULL;
    int len;
	if(!bofstart())
	{
		return;
	}
	BeaconDataParse(&parser, Buffer, Length);
    domain = (wchar_t *)BeaconDataExtract(&parser, &len);
    rdomain = domain = *domain == 0 ? NULL: domain;
    if(domain != NULL)
    {
        rdomain = intAlloc(len); // The memory returned by BeaconDataExtract is not valid for our call into NetServerEnum, that's why we make this copy.  BOF crashes if we don't
        memcpy(rdomain, domain, len);
    }
    netview_enum(rdomain);
	printoutput(TRUE);
    if(rdomain != NULL)
        intFree(rdomain);
	bofstop();
}
#else
int main(int argc, char ** argv)
{
        if(!bofstart())
                return 1;
        char * target = argv[1];
        char * server = argv[2];
        unsigned short type = (unsigned short)atoi(argv[3]);
        query_domain(target, type,server);
        printoutput();
        bofstop();
        return 0;
}
#endif