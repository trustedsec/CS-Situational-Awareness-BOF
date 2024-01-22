#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "lm.h"
#include "lmaccess.h"


void ListServerGroupMembers(const wchar_t * server, const wchar_t * groupname)
{
	PLOCALGROUP_MEMBERS_INFO_2 pBuff = NULL, p = NULL;
	DWORD dwTotal = 0, dwRead = 0;
	DWORD_PTR hResume = 0; // this should really just have been a handle MS
	NET_API_STATUS res = 0;
	do{
		res = NETAPI32$NetLocalGroupGetMembers(server, groupname, 2, (LPBYTE *) &pBuff, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &hResume);
		if((res==ERROR_SUCCESS) || (res==ERROR_MORE_DATA))
		{
			p = pBuff;
			for(;dwRead>0;dwRead--)
			{
				// convert sid to string
				wchar_t * sidstr = NULL;
				ADVAPI32$ConvertSidToStringSidW(p->lgrmi2_sid, &sidstr);

				internal_printf("----------Local Group Member----------\n");
				
				if (server == NULL)
				{
					// get FQDN for localhost
					wchar_t hostname[256] = {0};
					DWORD hostname_len = 256;
					KERNEL32$GetComputerNameExW(ComputerNameDnsFullyQualified, (LPWSTR)&hostname, &hostname_len);
					internal_printf("Host: %S\n", hostname);
				}
				else{
					// otherwise use what the operator gave us
					internal_printf("Host: %S\n", server);
				}
				internal_printf("Group: %S\n", groupname);
				internal_printf("Member: %S\n", p->lgrmi2_domainandname);
				internal_printf("MemberSid: %S\n", sidstr);
				
				// check if the sid type is user, group etc
				if (p->lgrmi2_sidusage == SidTypeUser)
				{
					internal_printf("MemberSidType: User\n");
				}
				else if (p->lgrmi2_sidusage == SidTypeGroup)
				{
					internal_printf("MemberSidType: Group\n");
				}
				else if (p->lgrmi2_sidusage == SidTypeWellKnownGroup)
				{
					internal_printf("MemberSidType: WellKnownGroup\n");
				}
				else if (p->lgrmi2_sidusage == SidTypeDeletedAccount)
				{
					internal_printf("MemberSidType: DeletedAccount\n");
				}
				else if (p->lgrmi2_sidusage == SidTypeUnknown)
				{
					internal_printf("MemberSidType: Unknown\n");
				}

				internal_printf("--------End Local Group Member--------\n\n");
				p++;
			}
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
	const wchar_t * server = (wchar_t *)BeaconDataExtract(&parser, NULL);
	const wchar_t * group = (wchar_t *)BeaconDataExtract(&parser, NULL);
	server = (*server == 0) ? NULL: server;
	group = (*group == 0) ? NULL: group;


	
	if(!bofstart())
	{
		return;
	}

	if(group == NULL)
	{
		internal_printf("[*] Querying Remote Desktop Users...\n");
		ListServerGroupMembers(server, L"Remote Desktop Users");

		internal_printf("[*] Querying Distributed COM Users...\n");
		ListServerGroupMembers(server, L"Distributed COM Users");

		internal_printf("[*] Querying Remote Management Users...\n");
		ListServerGroupMembers(server, L"Remote Management Users");

		internal_printf("[*] Querying Administrators...\n");
		ListServerGroupMembers(server, L"Administrators");
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
	ListServerGroupMembers(NULL, L"Administrators");
	ListServerGroupMembers(L"172.31.0.1", L"Administrators");
	ListServerGroupMembers(NULL, L"asdf");
	ListServerGroupMembers(L"172.31.0.1", L"asdf");
	ListServerGroupMembers(L"asdf", L"Administrators");
}

#endif
