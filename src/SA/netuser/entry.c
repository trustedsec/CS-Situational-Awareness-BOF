#include <windows.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdlib.h>
#include "lmaccess.h"
#include "lmerr.h"
#include "lm.h"
#include "bofdefs.h"
#include "base.c"

#define TICKSTO1970         0x019db1ded53e8000LL
#define TICKSTO1980         0x01a8e79fe1d58000LL
#define TICKSPERSEC        10000000
#ifdef _WIN64 //can't use builtin function for extended division on x86
DWORD GetTimeInSeconds(VOID)
{
    LARGE_INTEGER Time;
    FILETIME FileTime;
    DWORD dwSeconds;
    int junk = 0;
    lldiv_t test;
    KERNEL32$GetSystemTimeAsFileTime(&FileTime);
    Time.u.LowPart = FileTime.dwLowDateTime;
    Time.u.HighPart = FileTime.dwHighDateTime;
    Time.QuadPart = Time.QuadPart - TICKSTO1970;
    Time.QuadPart = (uint64_t)Time.QuadPart / (uint64_t)TICKSPERSEC;
    dwSeconds = Time.u.LowPart;

    return dwSeconds;
}
#endif
void PrintDateTime(DWORD dwSeconds)
{
    LARGE_INTEGER Time;
    FILETIME FileTime;
    SYSTEMTIME SystemTime;
    WCHAR DateBuffer[80];
    WCHAR TimeBuffer[80];

    //RtlSecondsSince1970ToTime(dwSeconds, &Time);
    Time.QuadPart = ((LONGLONG)dwSeconds * TICKSPERSEC) + TICKSTO1970;
    FileTime.dwLowDateTime = Time.u.LowPart;
    FileTime.dwHighDateTime = Time.u.HighPart;
    KERNEL32$FileTimeToLocalFileTime(&FileTime, &FileTime);
    KERNEL32$FileTimeToSystemTime(&FileTime, &SystemTime);

    KERNEL32$GetDateFormatW(LOCALE_USER_DEFAULT,
                   DATE_SHORTDATE,
                   &SystemTime,
                   NULL,
                   DateBuffer,
                   ARRAYSIZE(DateBuffer));

    KERNEL32$GetDateFormatW(LOCALE_USER_DEFAULT,
                   TIME_NOSECONDS,
                   &SystemTime,
                   NULL,
                   TimeBuffer,
                   ARRAYSIZE(TimeBuffer));

    internal_printf("%S %S", DateBuffer, TimeBuffer);
}

void netuserinfo(wchar_t* username, wchar_t* hostname){
    LPUSER_INFO_4 pBuf4 = NULL;
    NET_API_STATUS nStatus;
    NET_API_STATUS gStatus;
    NET_API_STATUS lgStatus;
    NET_API_STATUS umStatus;
    PGROUP_USERS_INFO_0 pGroupInfo = NULL;
    PLOCALGROUP_USERS_INFO_0 pLocalGroupInfo = NULL;
    PUSER_MODALS_INFO_0 pUserModals = NULL;
    DWORD dwGroupRead = 0, dwGroupTotal = 0;
    DWORD dwLocalGroupRead = 0, dwLocalGroupTotal = 0;
    int gcount = 0;
    DWORD lastset = 0;
    umStatus = NETAPI32$NetUserModalsGet(hostname,
                              0,
                              (LPBYTE*)&pUserModals);
    nStatus = NETAPI32$NetUserGetInfo(hostname, username, 4, (LPBYTE *) &pBuf4);
    if (nStatus == NERR_Success){
        internal_printf("User name:\t\t\t%S\n", pBuf4->usri4_name == NULL ? L"" : pBuf4->usri4_name);
        internal_printf("Full Name:\t\t\t%S\n", pBuf4->usri4_full_name == NULL ? L"" : pBuf4->usri4_full_name);
        internal_printf("User's comment:\t\t%S\n", pBuf4->usri4_usr_comment == NULL ? L"" : pBuf4->usri4_usr_comment);
        internal_printf("Country code:\t\t\t%ld\n", pBuf4->usri4_country_code);

        internal_printf("\n");

        internal_printf("Flags (account details hex):\t%lx\n", pBuf4->usri4_flags);

        internal_printf("Account enabled:\t\t\t");
        if (pBuf4->usri4_flags & UF_ACCOUNTDISABLE){
            internal_printf("No\n");
        }
        else{
            internal_printf("Yes\n");
        }

        internal_printf("Trusted for delegation:\t\t");
        if (pBuf4->usri4_flags & UF_TRUSTED_FOR_DELEGATION){
            internal_printf("Yes\n");
        }
        else{
            internal_printf("No\n");
        }

        internal_printf("Dont require preauth:\t\t");
        if (pBuf4->usri4_flags & UF_DONT_REQUIRE_PREAUTH){
            internal_printf("Yes\n");
        }
        else{
            internal_printf("No\n");
        }

        internal_printf("Account expires:\t\t\t");
        if (pBuf4->usri4_acct_expires == TIMEQ_FOREVER){
            internal_printf("Never");
        }
        else{
            PrintDateTime(pBuf4->usri4_acct_expires);
        }
        internal_printf("\n\n");
        internal_printf("Password last set:\t\t");
        #ifdef _WIN64

        lastset = GetTimeInSeconds() - pBuf4->usri4_password_age;
        PrintDateTime(lastset);
        #else
        internal_printf("not supported on x86 beacons\n");
        #endif
        internal_printf("\nPassword expires:\t\t\t");
        if (pBuf4->usri4_flags & UF_DONT_EXPIRE_PASSWD){
            internal_printf("Never");
        }
        else {
            if (umStatus == NERR_Success){
                if (pUserModals->usrmod0_max_passwd_age == TIMEQ_FOREVER){
                    internal_printf("Never");
                }
                else{
                    PrintDateTime(lastset + pUserModals->usrmod0_max_passwd_age);
                }
            }
        }
	    
	internal_printf("\nPassword changeable:\t\t%s\n", "Not implemented");
        internal_printf("\nPassword required:\t\t");
        if (pBuf4->usri4_flags & UF_PASSWD_NOTREQD){
            internal_printf("No\n");
        }
        else{
            internal_printf("Yes\n");
        }
        internal_printf("User may change password:\t\t");
        if (pBuf4->usri4_flags & UF_PASSWD_CANT_CHANGE){
            internal_printf("No\n\n");
        }
        else{
            internal_printf("Yes\n\n");
        }
        internal_printf("Workstations allowed:\t\t");
        if (pBuf4->usri4_workstations == NULL || MSVCRT$wcslen(pBuf4->usri4_workstations) == 0){
            internal_printf("ALL\n");
        }
        else{
            internal_printf("%S\n", pBuf4->usri4_workstations);
        }
        internal_printf("Script path:\t\t\t%S\n", pBuf4->usri4_script_path == NULL ? L"": pBuf4->usri4_script_path);
        internal_printf("User profile:\t\t\t%S\n", pBuf4->usri4_profile == NULL ? L"": pBuf4->usri4_profile);
        internal_printf("Home directory:\t\t\t%S\n", pBuf4->usri4_home_dir == NULL ? L"" :pBuf4->usri4_home_dir);
        internal_printf("Last logon:\t\t\t");
        if (pBuf4->usri4_flags & UF_LOCKOUT){
            internal_printf("Account is locked out!\n");
        }
        PrintDateTime(pBuf4->usri4_last_logon);
        internal_printf("\n");
        
        lgStatus = NETAPI32$NetUserGetLocalGroups(NULL,
                                username,
                                0,
                                0,
                                (LPBYTE*)&pLocalGroupInfo,
                                MAX_PREFERRED_LENGTH,
                                &dwLocalGroupRead,
                                &dwLocalGroupTotal);
        gStatus = NETAPI32$NetUserGetGroups(hostname,
                            username,
                            0,
                            (LPBYTE*)&pGroupInfo,
                            MAX_PREFERRED_LENGTH,
                            &dwGroupRead,
                            &dwGroupTotal);
        if (lgStatus == NERR_Success){
            internal_printf("Local Group Memberships:\n");
            for (gcount=0; gcount < dwLocalGroupTotal; gcount++){
                internal_printf("\t%S\n", pLocalGroupInfo[gcount].lgrui0_name);
            }
        }
        if (gStatus == NERR_Success){
            internal_printf("Global Group memberships:\n");
            for (gcount=0; gcount < dwGroupTotal; gcount++){
                internal_printf("\t%S\n", pGroupInfo[gcount].grui0_name);
            }
        }
        else{
            internal_printf("Failed to get group info\n");
        }
        

    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "Failed to get user info");

    }
    
    if (pBuf4){
        NETAPI32$NetApiBufferFree(pBuf4);
    }
    if (pGroupInfo){
        NETAPI32$NetApiBufferFree(pGroupInfo);
    }
    if (pLocalGroupInfo){
        NETAPI32$NetApiBufferFree(pLocalGroupInfo);
    }
    if (pUserModals){
        NETAPI32$NetApiBufferFree(pUserModals);
    }
}

#ifdef BOF

VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
    datap parser;
    wchar_t *username = NULL;
    wchar_t *domain = NULL;
	if(!bofstart())
	{
		return;
	}
    BeaconDataParse(&parser, Buffer, Length);
    username = (wchar_t *)BeaconDataExtract(&parser, NULL);
    domain = (wchar_t *)BeaconDataExtract(&parser, NULL);
    domain = *domain == 0 ? NULL : domain;
    netuserinfo(username, domain);

	printoutput(TRUE);
};

#else

int main()
{
netuserinfo(L"testuser", L"testrange.local");
netuserinfo(L"user", NULL);
netuserinfo(L"asdf", NULL);
netuserinfo(L"nopenope", L"nope");
netuserinfo(L"nope", L"testrange.local");
return 0;
}

#endif
