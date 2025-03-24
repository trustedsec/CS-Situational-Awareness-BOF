#include <windows.h>
#include "dsreg.h"
#include "bofdefs.h"
#include "base.c"

void GetAadJoinInfo()
{
	// https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation
	
	DWORD res;
	PDSREG_JOIN_INFO pJoinInfo;
	res = NETAPI32$NetGetAadJoinInformation(NULL, &pJoinInfo);
	
	if (res == 0)
	{
		internal_printf("\n================== AAD/Entra ID Join Info ==================\n");
		switch (pJoinInfo->joinType)
		{
			case DSREG_DEVICE_JOIN:
				internal_printf("%-20s: %s\n", "Join Type", "Device join");
				break;
			case DSREG_WORKPLACE_JOIN:
				internal_printf("%-20s: %s\n", "Join Type", "Workplace join");
				break;
			default:
				internal_printf("%-20s: %s\n", "Join Type", "Unknown");
				break;
		}
		internal_printf("%-20s: %S\n", "Device ID", pJoinInfo->pszDeviceId);
		internal_printf("%-20s: %S\n", "IDP Domain", pJoinInfo->pszIdpDomain);
		internal_printf("%-20s: %S\n", "Tenant ID", pJoinInfo->pszTenantId);
		internal_printf("%-20s: %S\n", "Tenant Display Name", pJoinInfo->pszTenantDisplayName);
		internal_printf("%-20s: %S\n", "Join User Email", pJoinInfo->pszJoinUserEmail);
		//internal_printf("%-20s: %S\n", "MDM Enrollment URL", pJoinInfo->pszMdmEnrollmentUrl);
		//internal_printf("%-20s: %S\n", "MDM Terms of Use URL", pJoinInfo->pszMdmTermsOfUseUrl);
		//internal_printf("%-20s: %S\n", "MDM Compliance URL", pJoinInfo->pszMdmComplianceUrl);
		//internal_printf("%-20s: %S\n", "User Setting Sync URL", pJoinInfo->pszUserSettingSyncUrl);
		
		//
		// Only get join user info if type is DSREG_DEVICE_JOIN
		//
		if (pJoinInfo->joinType == DSREG_DEVICE_JOIN)
		{
			internal_printf("\n====================== Join User Info ======================\n");
			internal_printf("%-20s: %S\n", "User Email", pJoinInfo->pUserInfo->pszUserEmail);
			internal_printf("%-20s: %S\n", "User Key ID", pJoinInfo->pUserInfo->pszUserKeyId);
			
			//
			// Extract User SID from pszUserKeyName
			//

			// internal_printf("%-20s: %S\n", "User Key Name", pJoinInfo->pUserInfo->pszUserKeyName);
			if (pJoinInfo->pUserInfo->pszUserKeyName != NULL)
			{
				WCHAR userSid[256] = {0};
				WCHAR *slashPos = MSVCRT$wcschr(pJoinInfo->pUserInfo->pszUserKeyName, L'/');
				if (slashPos != NULL)
				{
					size_t sidLength = slashPos - pJoinInfo->pUserInfo->pszUserKeyName;
					MSVCRT$wcsncpy_s(userSid, sizeof(userSid) / sizeof(WCHAR), pJoinInfo->pUserInfo->pszUserKeyName, sidLength);
					internal_printf("%-20s: %S\n", "User SID", userSid);
				}
			}
		} else {
			internal_printf("\n[-] Device not joined to AAD, skipping join user info\n");
		}
	
	//
	// NetGetAadJoinInformation failed 
	//
	} else {
		internal_printf("[-] Error: %d\n", res);
		internal_printf("[-] Host may not be cloud joined\n");
	}

	//
	// Free the join info
	//
	if (pJoinInfo != NULL)
	{
		NETAPI32$NetFreeAadJoinInformation(pJoinInfo);
	}
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	if(!bofstart())
	{
		return;
	}
	GetAadJoinInfo();
	printoutput(TRUE);
};

#else

int main()
{
	GetAadJoinInfo();
	return 0;
}

#endif
