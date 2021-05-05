#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "lm.h"
#include "lmaccess.h"

//Code taken from example code at https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netquerydisplayinformation
void ListDomainGroups(const wchar_t * domain)
{
	PNET_DISPLAY_GROUP pBuff = NULL, p = NULL;
	DWORD res = 0, dwRec = 0, i = 0;

	do // begin do
	{ 

		res = NETAPI32$NetQueryDisplayInformation(domain, 3, i, 100, MAX_PREFERRED_LENGTH, &dwRec, (PVOID*) &pBuff);
		if((res==ERROR_SUCCESS) || (res==ERROR_MORE_DATA) && dwRec != 0 && pBuff != NULL)
		{
			p = pBuff;
			for(;dwRec>0;dwRec--)
			{
				internal_printf("Name:      %S\n"
				"Comment:   %S\n"
				"Group ID:  %lu\n"
				"Attributes: %lu\n"
				"--------------------------------\n",
				p->grpi3_name,
				p->grpi3_comment,
				p->grpi3_group_id,
				p->grpi3_attributes);
				i = p->grpi3_next_index;
				p++;
			}
			NETAPI32$NetApiBufferFree(pBuff);
			pBuff = NULL;
		}
		else
		{
			BeaconPrintf(CALLBACK_ERROR, "Error: %lu\n", res);
		}
	} while (res==ERROR_MORE_DATA); // end do
}


void ListGlobalGroupMembers(const wchar_t * domain, const wchar_t * groupname)
{
	PGROUP_INFO_0 pBuff = NULL, p = NULL;
	DWORD dwTotal = 0, dwRead = 0, i = 0;
	DWORD_PTR hResume = 0; // this should really just have been a handle MS
	NET_API_STATUS res = 0;
	do{
		res = NETAPI32$NetGroupGetUsers(domain, groupname, 0, (LPBYTE *) &pBuff, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &hResume);
		if((res==ERROR_SUCCESS) || (res==ERROR_MORE_DATA))
		{
			p = pBuff;
			for(;dwRead>0;dwRead--)
			{
				internal_printf("%-20S  ", p->grpi0_name);
				if(++i % 3 == 0)
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
	const wchar_t * domain = (wchar_t *)BeaconDataExtract(&parser, NULL);
	const wchar_t * group = (wchar_t *)BeaconDataExtract(&parser, NULL);
	domain = (*domain == 0) ? NULL: domain;
	group = (*group == 0) ? NULL: group;
	wchar_t default_domain[256] = {0};
	DWORD dwDefaultSize = 256;

	
	if(!bofstart())
	{
		return;
	}
	if(domain == NULL)
	{
		if(KERNEL32$GetComputerNameExW(ComputerNameDnsDomain, (LPWSTR)&default_domain, &dwDefaultSize) == 0)
		{
			BeaconPrintf(CALLBACK_ERROR, "Warning, could not get default domain name, continuing against local system");
		}
		else
		{
			BeaconPrintf(CALLBACK_OUTPUT, "Using Resolved domain of %S", default_domain);
			domain = default_domain;
		}
		
	}

	if(type == 0)
	{
		ListDomainGroups(domain);
	}
	else
	{
		ListGlobalGroupMembers(domain, group);
	}
	printoutput(TRUE);
};

#else

int main()
{

	wchar_t default_domain[256] = {0};
	DWORD dwDefaultSize = 256;

	if(KERNEL32$GetComputerNameExW(ComputerNameDnsDomain, (LPWSTR)&default_domain, &dwDefaultSize) == 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "Warning, could not get default domain name, continuing against local system");
	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "Using Resolved domain of %S", default_domain);
	}
	ListDomainGroups(default_domain);
	ListDomainGroups(L"testrange.local");
	ListDomainGroups(L"asdf");
	ListGlobalGroupMembers(default_domain, L"Domain Admins");
	ListGlobalGroupMembers(L"testrange.local", L"Domain Admins");
	ListGlobalGroupMembers(default_domain, L"asdf");
	ListGlobalGroupMembers(L"asdf", L"Administrators");
}

#endif
