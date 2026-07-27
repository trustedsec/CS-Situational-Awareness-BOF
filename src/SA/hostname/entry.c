#include <windows.h>
#include "bofdefs.h"
#include "base.c"

// Constants
#define NERR_Success 0
#define NetSetupUnknownStatus 0
#define NetSetupUnjoined 1
#define NetSetupWorkgroupName 2
#define NetSetupDomainName 3

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

	WCHAR wcHostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
	DWORD dwHostnameSize = MAX_COMPUTERNAME_LENGTH + 1;
	WCHAR wcFQDN[256] = {0};
	DWORD dwFqdnSize = 256;
	LPWSTR lpNetbiosDomain = NULL;
	DWORD joinStatus = NetSetupUnknownStatus;
	DWORD dwRet = 0;

	// Get NetBIOS hostname using GetComputerNameExW with ComputerNameNetBIOS
	if (!KERNEL32$GetComputerNameExW(ComputerNameNetBIOS, wcHostname, &dwHostnameSize)) {
		BeaconPrintf(CALLBACK_ERROR, "GetComputerNameExW failed: %d", KERNEL32$GetLastError());
		goto cleanup;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[*] Computer Name: %ls", wcHostname);

	// Use NetGetJoinInformation to detect domain status
	dwRet = NETAPI32$NetGetJoinInformation(NULL, &lpNetbiosDomain, (DWORD*)&joinStatus);

	if (dwRet == NERR_Success) {
		if (joinStatus == NetSetupDomainName) {
			// Domain joined - get FQDN using GetComputerNameExW
			dwFqdnSize = 256;
			if (KERNEL32$GetComputerNameExW(ComputerNameDnsFullyQualified, wcFQDN, &dwFqdnSize)) {
				BeaconPrintf(CALLBACK_OUTPUT, "[+] FQDN: %ls", wcFQDN);
			} else {
				BeaconPrintf(CALLBACK_ERROR, "GetComputerNameExW (FQDN) failed: %d", KERNEL32$GetLastError());
			}
		} else if (joinStatus == NetSetupWorkgroupName) {
			// Workgroup member
			BeaconPrintf(CALLBACK_OUTPUT, "[-] Not domain joined (workgroup member)");
			if (lpNetbiosDomain && MSVCRT$wcslen(lpNetbiosDomain) > 0) {
				BeaconPrintf(CALLBACK_OUTPUT, "[*] Workgroup: %ls", lpNetbiosDomain);
			}
		} else {
			// Unknown status
			BeaconPrintf(CALLBACK_OUTPUT, "[-] Unknown join status: %d", joinStatus);
		}

		if (lpNetbiosDomain) {
			NETAPI32$NetApiBufferFree(lpNetbiosDomain);
		}
	} else {
		BeaconPrintf(CALLBACK_ERROR, "NetGetJoinInformation failed: 0x%08X", dwRet);
	}

cleanup:
	printoutput(TRUE);
}

#else

#include <stdio.h>
#include <string.h>

#define NERR_Success 0
#define NetSetupUnknownStatus 0
#define NetSetupUnjoined 1
#define NetSetupWorkgroupName 2
#define NetSetupDomainName 3

int main()
{
	// Standalone version for testing/leak checks
	WCHAR wcHostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
	DWORD dwHostnameSize = MAX_COMPUTERNAME_LENGTH + 1;
	WCHAR wcFQDN[256] = {0};
	DWORD dwFqdnSize = 256;
	LPWSTR lpNetbiosDomain = NULL;
	DWORD joinStatus = NetSetupUnknownStatus;
	DWORD dwRet = 0;

	// Get hostname
	if (GetComputerNameExW(ComputerNameNetBIOS, wcHostname, &dwHostnameSize)) {
		wprintf(L"[*] Computer Name: %ls\n", wcHostname);

		// Use NetGetJoinInformation to detect domain status
		dwRet = NetGetJoinInformation(NULL, &lpNetbiosDomain, &joinStatus);

		if (dwRet == NERR_Success) {
			if (joinStatus == NetSetupDomainName) {
				// Domain joined - get FQDN using GetComputerNameExW
				dwFqdnSize = 256;
				if (GetComputerNameExW(ComputerNameDnsFullyQualified, wcFQDN, &dwFqdnSize)) {
					wprintf(L"[+] FQDN: %ls\n", wcFQDN);
				} else {
					printf("[-] GetComputerNameExW (FQDN) failed\n");
				}
			} else if (joinStatus == NetSetupWorkgroupName) {
				wprintf(L"[-] Not domain joined (workgroup member)\n");
				if (lpNetbiosDomain) {
					wprintf(L"[*] Workgroup: %ls\n", lpNetbiosDomain);
				}
			}

			if (lpNetbiosDomain) {
				NetApiBufferFree(lpNetbiosDomain);
			}
		} else {
			printf("[-] NetGetJoinInformation failed: 0x%08X\n", dwRet);
		}
	} else {
		printf("[-] GetComputerNameExW failed\n");
	}

	return 0;
}

#endif