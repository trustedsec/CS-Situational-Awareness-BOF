/*
 * PROJECT:     ReactOS Whoami
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        base/applications/cmdutils/whoami/whoami.c
 * PURPOSE:     Displays information about the current local user, groups and privileges.
 * PROGRAMMERS: Ismael Ferreras Morezuelas (swyterzone+ros@gmail.com)
 */

#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <sddl.h>
#include "bofdefs.h"
#include "base.c"


typedef struct
{
    UINT Rows;
    UINT Cols;
    LPWSTR Content[1];
} WhoamiTable;

char* WhoamiGetUser(EXTENDED_NAME_FORMAT NameFormat)
{
    char* UsrBuf = intAlloc(MAX_PATH);
    ULONG UsrSiz = MAX_PATH;

    if (UsrBuf == NULL)
        return NULL;

    if (SECUR32$GetUserNameExA(NameFormat, UsrBuf, &UsrSiz))
    {
        return UsrBuf;
    }

    intFree(UsrBuf);
    return NULL;
}

VOID* WhoamiGetTokenInfo(TOKEN_INFORMATION_CLASS TokenType)
{
    HANDLE hToken = 0;
    DWORD dwLength = 0;
    VOID* pTokenInfo = 0;

    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_READ, &hToken))
    {
        ADVAPI32$GetTokenInformation(hToken,
                            TokenType,
                            NULL,
                            dwLength,
                            &dwLength);

        if (KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            pTokenInfo = intAlloc(dwLength);
            if (pTokenInfo == NULL)
            {
                //printf("ERROR: not enough memory to allocate the token structure.\r\n");
                return NULL;
            }
        }

        if (!ADVAPI32$GetTokenInformation(hToken, TokenType,
                                 (LPVOID)pTokenInfo,
                                 dwLength,
                                 &dwLength))
        {
            //printf("ERROR 0x%x: could not get token information.\r\n", GetLastError());
            intFree(pTokenInfo);
            return NULL;
        }

        KERNEL32$CloseHandle(hToken);
    }

    return pTokenInfo;
}



int WhoamiUser(void)
{
    PTOKEN_USER pUserInfo = (PTOKEN_USER) WhoamiGetTokenInfo(TokenUser);
    char* pUserStr = NULL;
    char* pSidStr = NULL;
    WhoamiTable *UserTable = NULL;

    if (pUserInfo == NULL)
    {
        return 1;
    }

    pUserStr = WhoamiGetUser(NameSamCompatible);
    if (pUserStr == NULL)
    {
        intFree(pUserInfo);
        return 1;
    }



    internal_printf("\nUserName\t\tSID\n");
    internal_printf("====================== ====================================\n");

    ADVAPI32$ConvertSidToStringSidA(pUserInfo->User.Sid, &pSidStr);

    internal_printf("%s\t%s\n\n", pUserStr, pSidStr);


    /* cleanup our allocations */
    KERNEL32$LocalFree(pSidStr);
    intFree(pUserInfo);
    intFree(pUserStr);

    return 0;
}

int WhoamiGroups(void)
{
    DWORD dwIndex = 0;
    char* pSidStr = NULL;

    char szGroupName[255] = {0};
    char szDomainName[255] = {0};

    DWORD cchGroupName  = _countof(szGroupName);
    DWORD cchDomainName = _countof(szGroupName);

    SID_NAME_USE Use = 0;
    BYTE SidNameUseStr[12] =
    {
        /* SidTypeUser           */ -1,
        /* SidTypeGroup          */ -1,
        /* SidTypeDomain         */ -1,
        /* SidTypeUser           */ -1,
        /* SidTypeAlias          */ 12,
        /* SidTypeWellKnownGroup */ 11,
        /* SidTypeDeletedAccount */ -1,
        /* SidTypeInvalid        */ -1,
        /* SidTypeUnknown        */ -1,
        /* SidTypeComputer       */ -1,
        /* SidTypeLabel          */ 13
    };

    PTOKEN_GROUPS pGroupInfo = (PTOKEN_GROUPS)WhoamiGetTokenInfo(TokenGroups);
    WhoamiTable *GroupTable = NULL;

    if (pGroupInfo == NULL)
    {
        return 1;
    }

    /* the header is the first (0) row, so we start in the second one (1) */


    internal_printf("\n%-50s%-25s%-25s%-25s\n", "GROUP INFORMATION", "Type", "SID", "Attributes");
    internal_printf("================================================= ===================== ================ ==================================================\n");

    for (dwIndex = 0; dwIndex < pGroupInfo->GroupCount; dwIndex++)
    {
        ADVAPI32$LookupAccountSidA(NULL,
                          pGroupInfo->Groups[dwIndex].Sid,
                          (LPSTR)&szGroupName,
                          &cchGroupName,
                          (LPSTR)&szDomainName,
                          &cchDomainName,
                          &Use);

        /* the original tool seems to limit the list to these kind of SID items */
        if ((Use == SidTypeWellKnownGroup || Use == SidTypeAlias ||
            Use == SidTypeLabel) && !(pGroupInfo->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID))
        {
                char tmpBuffer[666];

            /* looks like windows treats 0x60 as 0x7 for some reason, let's just nod and call it a day:
               0x60 is SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED
               0x07 is SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED */

            if (pGroupInfo->Groups[dwIndex].Attributes == 0x60)
                pGroupInfo->Groups[dwIndex].Attributes = 0x07;

            /* 1- format it as DOMAIN\GROUP if the domain exists, or just GROUP if not */
            MSVCRT$sprintf((char*)&tmpBuffer, "%s%s%s", szDomainName, cchDomainName ? "\\" : "", szGroupName);
            internal_printf("%-50s", tmpBuffer);

            /* 2- let's find out the group type by using a simple lookup table for lack of a better method */
            if (Use == SidTypeWellKnownGroup){
                internal_printf("%-25s", "Well-known group ");
            }
            else if (Use == SidTypeAlias){
                internal_printf("%-25s", "Alias ");
            }
            else if (Use == SidTypeLabel){
                internal_printf("%-25s", "Label ");
            }
            /* 3- turn that SID into text-form */
            ADVAPI32$ConvertSidToStringSidA(pGroupInfo->Groups[dwIndex].Sid, &pSidStr);

            //WhoamiSetTable(GroupTable, pSidStr, PrintingRow, 2);
            internal_printf("%-25s", pSidStr);

            KERNEL32$LocalFree(pSidStr);

            /* 4- reuse that buffer for appending the attributes in text-form at the very end */
            ZeroMemory(tmpBuffer, sizeof(tmpBuffer));

            if (pGroupInfo->Groups[dwIndex].Attributes & SE_GROUP_MANDATORY)
                internal_printf("Mandatory group, ");
            if (pGroupInfo->Groups[dwIndex].Attributes & SE_GROUP_ENABLED_BY_DEFAULT)
                internal_printf("Enabled by default, ");
            if (pGroupInfo->Groups[dwIndex].Attributes & SE_GROUP_ENABLED)
                internal_printf("Enabled group, ");
            if (pGroupInfo->Groups[dwIndex].Attributes & SE_GROUP_OWNER)
                internal_printf("Group owner, ");

        }
        internal_printf("\n");
        /* reset the buffers so that we can reuse them */
        ZeroMemory(szGroupName, sizeof(szGroupName));
        ZeroMemory(szDomainName, sizeof(szDomainName));

        cchGroupName = 255;
        cchDomainName = 255;
    }


    /* cleanup our allocations */
    intFree(pGroupInfo);

    return 0;
}

int WhoamiPriv(void)
{
    PTOKEN_PRIVILEGES pPrivInfo = (PTOKEN_PRIVILEGES) WhoamiGetTokenInfo(TokenPrivileges);
    DWORD dwResult = 0, dwIndex = 0;
    WhoamiTable *PrivTable = NULL;

    if (pPrivInfo == NULL)
    {
        return 1;
    }

    internal_printf("\n\n%-30s%-50s%-30s\n", "Privilege Name", "Description", "State");
    internal_printf("============================= ================================================= ===========================\n");

    for (dwIndex = 0; dwIndex < pPrivInfo->PrivilegeCount; dwIndex++)
    {
        char* PrivName = NULL;
        char* DispName = NULL;
        DWORD PrivNameSize = 0, DispNameSize = 0;
        BOOL ret = FALSE;

        ret = ADVAPI32$LookupPrivilegeNameA(NULL,
                                   &pPrivInfo->Privileges[dwIndex].Luid,
                                   NULL,
                                   &PrivNameSize);

        PrivName = intAlloc(++PrivNameSize);

        ADVAPI32$LookupPrivilegeNameA(NULL,
                             &pPrivInfo->Privileges[dwIndex].Luid,
                             PrivName,
                             &PrivNameSize);

        //WhoamiSetTableDyn(PrivTable, PrivName, dwIndex + 1, 0);
        internal_printf("%-30s", PrivName);


        /* try to grab the size of the string, also, beware, as this call is
           unimplemented in ReactOS/Wine at the moment */

        ADVAPI32$LookupPrivilegeDisplayNameA(NULL, PrivName, NULL, &DispNameSize, &dwResult);

        DispName = intAlloc(++DispNameSize);

        ret = ADVAPI32$LookupPrivilegeDisplayNameA(NULL, PrivName, DispName, &DispNameSize, &dwResult);
        if(PrivName != NULL)
            intFree(PrivName);
        if (ret && DispName)
        {
            internal_printf("%-50s", DispName);
        }
        else
        {
            internal_printf("%-50s", "???");
        }
        if (DispName != NULL)
                intFree(DispName);

        if (pPrivInfo->Privileges[dwIndex].Attributes & SE_PRIVILEGE_ENABLED)
            internal_printf("%-30s\n", "Enabled");
        else
            internal_printf("%-30s\n", "Disabled");
    }


    /* cleanup our allocations */
    intFree(pPrivInfo);

    return 0;
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
	(void)WhoamiUser();
	(void)WhoamiGroups();
	(void)WhoamiPriv();
	printoutput(TRUE);
	bofstop();
};
