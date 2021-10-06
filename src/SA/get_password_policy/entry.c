#include <windows.h>
#include <lm.h>
#include "bofdefs.h"
#include "base.c"

void get_password_policy(const wchar_t * serverName)
{
   USER_MODALS_INFO_0 *pBuf = NULL;
   NET_API_STATUS nStatus;
   DWORD result = 0;
   char strresult[256] = {0};
   //#thanksMSDN https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsget
   nStatus = NETAPI32$NetUserModalsGet((LPCWSTR) serverName,
                              0,
                              (LPBYTE *)&pBuf);
   if (nStatus == NERR_Success)
   {
      if (pBuf != NULL)
      {
         internal_printf("Minimum password length:  %lu\n", pBuf->usrmod0_min_passwd_len);
		 result = pBuf->usrmod0_max_passwd_age/86400;
         internal_printf("Maximum password age (days): %s\n", (result > 1000) ? "Unlimited" : MSVCRT$_ultoa(result,strresult, 10 ));
         internal_printf("Minimum password age (days): %d\n", pBuf->usrmod0_min_passwd_age/86400);
         internal_printf("Forced log off time (seconds):  %s\n", (pBuf->usrmod0_force_logoff == UINT_MAX) ? "Never" : MSVCRT$_ultoa(pBuf->usrmod0_force_logoff, strresult, 10));
         internal_printf("Password history length:  %s\n", (pBuf->usrmod0_password_hist_len == 0) ? "None" : MSVCRT$_ultoa(pBuf->usrmod0_password_hist_len, strresult, 10));
		 NETAPI32$NetApiBufferFree(pBuf); pBuf = NULL;
      }
	  else
	  {
		  internal_printf("somehow call worked but we didn't get memory? (BROKEN)");
	  }  
   }
   else
   {
      internal_printf("A system error has occurred(modal 0): %d\n", nStatus);
	  goto end;
   }
   nStatus = NETAPI32$NetUserModalsGet((LPCWSTR) serverName,
                              3,
                              (LPBYTE *)&pBuf);
   if (nStatus == NERR_Success)
   {
      if (pBuf != NULL)
      {
		 result = ((PUSER_MODALS_INFO_3)pBuf)->usrmod3_lockout_duration;
         internal_printf("Lockout duration (minutes):  %s\n", (result == UINT_MAX) ? "Until Admin Unlock" : MSVCRT$_ultoa(result / 60, strresult, 10));
		 internal_printf("Lockout observation window (minutes):  %d\n", ((PUSER_MODALS_INFO_3)pBuf)->usrmod3_lockout_observation_window / 60);
		 result = ((PUSER_MODALS_INFO_3)pBuf)->usrmod3_lockout_threshold;
		 internal_printf("Lockout threshold:  %s\n", (result == 0) ? "Accounts don't lock" : MSVCRT$_ultoa(result, strresult, 10));
		 NETAPI32$NetApiBufferFree(pBuf); pBuf = NULL;
      }
		else
	  {
		  internal_printf("somehow call worked but we didn't get memory? (BROKEN)");
	  }
   }
   else
   {
      internal_printf("A system error has occurred(modal 3): %d\n", nStatus);
	  goto end;
   }

	end:
   //
   // Free the allocated memory.
   //
   if (pBuf != NULL)
      NETAPI32$NetApiBufferFree(pBuf);

}


#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	datap parser = {0};
	wchar_t * server = NULL;
	if(!bofstart())
	{
		return;
	}
	BeaconDataParse(&parser, Buffer, Length);
	server = (wchar_t *)BeaconDataExtract(&parser, NULL);
	server = (*(char *)server == 0) ? NULL : server;
	get_password_policy(server);
	printoutput(TRUE);
};

#else

int main()
{
//code for standalone exe for scanbuild / leak checks
}

#endif
