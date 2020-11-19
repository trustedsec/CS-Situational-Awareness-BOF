#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "lm.h"
#include "lmaccess.h"

//Code taken from example code at https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netquerydisplayinformation
void ListserverGroups(const wchar_t * server)
{
	PLOCALGROUP_INFO_1 pBuff = NULL, p = NULL;
	DWORD res = 0, dwRec = 0, dwTotal = 0;
	DWORD_PTR hResume = 0;
	do // begin do
	{ 

		res = NETAPI32$NetLocalGroupEnum(server, 1, (LPBYTE *)&pBuff, MAX_PREFERRED_LENGTH, &dwRec, &dwTotal, &hResume);
		if((res==ERROR_SUCCESS) || (res==ERROR_MORE_DATA))
		{
			p = pBuff;
			for(;dwRec>0;dwRec--)
			{
				internal_printf("Name:      %S\n"
				"Comment:   %S\n"
				"--------------------------------\n",
				p->lgrpi1_name,
				p->lgrpi1_comment);
				p++;
			}
			NETAPI32$NetApiBufferFree(pBuff);
		}
		else
		{
			BeaconPrintf(CALLBACK_ERROR, "Error: %lu\n", res);
		}
	} while (res==ERROR_MORE_DATA); // end do
}


void ListServerGroupMembers(const wchar_t * server, const wchar_t * groupname)
{
	PLOCALGROUP_MEMBERS_INFO_3 pBuff = NULL, p = NULL;
	DWORD dwTotal = 0, dwRead = 0, i = 0;
	DWORD_PTR hResume = 0; // this should really just have been a handle MS
	NET_API_STATUS res = 0;
	do{
		res = NETAPI32$NetLocalGroupGetMembers(server, groupname, 3, (LPBYTE *) &pBuff, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &hResume);
		if((res==ERROR_SUCCESS) || (res==ERROR_MORE_DATA))
		{
			p = pBuff;
			for(;dwRead>0;dwRead--)
			{
				internal_printf("%-40S  ", p->lgrmi3_domainandname);
				if(++i % 2 == 0)
				{
					internal_printf("\n");
				}
				p++;
			}
			i = 0;
			NETAPI32$NetApiBufferFree(pBuff);
		}
		else
		{
			BeaconPrintf(CALLBACK_ERROR, "Error: %lu\n", res);
		}
	} while(res == ERROR_MORE_DATA);
}

#ifdef BOF

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	const short type = BeaconDataShort(&parser);
	const wchar_t * server = (wchar_t *)BeaconDataExtract(&parser, NULL);
	const wchar_t * group = (wchar_t *)BeaconDataExtract(&parser, NULL);
	server = (*server == 0) ? NULL: server;
	group = (*group == 0) ? NULL: group;


	
	if(!bofstart())
	{
		return;
	}

	if(type == 0)
	{
		ListserverGroups(server);
	}
	else
	{
		ListServerGroupMembers(server, group);
	}
	printoutput(TRUE);
};

#else

int main()
{
	ListserverGroups(NULL);
	ListserverGroups(L"172.31.0.1");
	ListserverGroups(L"asdf");
	ListServerGroupMembers(NULL, L"Administrators");
	ListServerGroupMembers(L"172.31.0.1", L"Administrators");
	ListServerGroupMembers(NULL, L"asdf");
	ListServerGroupMembers(L"172.31.0.1", L"asdf");
	ListServerGroupMembers(L"asdf", L"Administrators");
}

#endif