#define SECURITY_WIN32
#include <windows.h>
#include <security.h>
#include "beacon.h"
#include <winldap.h>
#include <dsgetdc.h>
#include "../../common/bofdefs.h"

VERIFYSERVERCERT ServerCertCallback;
BOOLEAN _cdecl ServerCertCallback (PLDAP Connection, PCCERT_CONTEXT pServerCert)
{
	return TRUE;
}

BOOL checkLDAP(wchar_t* dc, wchar_t* spn, BOOL ssl)
{
	CredHandle hCredential;
	TimeStamp tsExpiry;
	SECURITY_STATUS getHandle = SECUR32$AcquireCredentialsHandleW(
		NULL,
		L"NTLM",
		SECPKG_CRED_OUTBOUND,
		NULL,
		NULL,
		NULL,
		NULL,
		&hCredential,
		&tsExpiry
	);

	if (getHandle != SEC_E_OK)
	{
		BeaconPrintf(CALLBACK_ERROR, "[-] AcquireCredentialsHandleW failed: %lu\n", getHandle);
		return FALSE;
	}

	//ldap
	ULONG result;
	LDAP* pLdapConnection = NULL;

	if(ssl == TRUE){
		pLdapConnection = WLDAP32$ldap_initW(dc, 636);
	}else{
		pLdapConnection = WLDAP32$ldap_initW(dc, 389);
	}
	if (pLdapConnection == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "[-] Failed to establish LDAP connection");
		return FALSE;
	}

	const int version = LDAP_VERSION3;
	result = WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_VERSION, (void*)&version);

	if(ssl == TRUE){
        WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_SSL, &result);  //LDAP_OPT_SSL
        if (result == 0)
            WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SSL, LDAP_OPT_ON);

        WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_SIGN, &result);  //LDAP_OPT_SIGN
        if (result == 0)
            WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SIGN, LDAP_OPT_ON);

        WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_ENCRYPT, &result);  //LDAP_OPT_ENCRYPT
        if (result == 0)
            WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_ENCRYPT, LDAP_OPT_ON);

        WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SERVER_CERTIFICATE, (void*)&ServerCertCallback ); //LDAP_OPT_SERVER_CERTIFICATE
	}

	result = WLDAP32$ldap_connect(pLdapConnection, NULL);
	if (result != LDAP_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[-] ldap_connect failed:");
		return FALSE;
	}

	ULONG res;
	struct berval* servresp = NULL;

	SecBufferDesc InBuffDesc;
	SecBuffer InSecBuff;

	SECURITY_STATUS initSecurity;
	CtxtHandle newContext;

	SecBuffer secbufPointer = { 0, SECBUFFER_TOKEN, NULL };
	SecBufferDesc output = { SECBUFFER_VERSION, 1, &secbufPointer };

	SecBuffer secbufPointer3 = { 0, SECBUFFER_TOKEN, NULL };
	SecBufferDesc output2 = { SECBUFFER_VERSION, 1, &secbufPointer };

	ULONG contextAttr;
	TimeStamp expiry;

	PSecBuffer ticket;
	int count = 0;
	//loop
	do {
		if(count > 5){
			BeaconPrintf(CALLBACK_ERROR, "[-] stuck in loop");
			break;
		}
		count++;
		if (servresp == NULL) {
			initSecurity = SECUR32$InitializeSecurityContextW(
				&hCredential,
				NULL,
				(SEC_WCHAR*)spn,
				ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE,
				0,
				SECURITY_NATIVE_DREP,
				NULL,
				0,
				&newContext,
				&output,
				&contextAttr,
				&expiry);

			ticket = output.pBuffers;
			//BeaconPrintf(CALLBACK_OUTPUT, "[-] size : %d\n", (DWORD)ticket->cbBuffer);

			if (ticket->pvBuffer == NULL) {
				BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW failed: %S\n", initSecurity);
				return FALSE;
			}

		}
		else {
			SecBuffer secbufPointer2 = { servresp->bv_len, SECBUFFER_TOKEN, servresp->bv_val };
			SecBufferDesc input = { SECBUFFER_VERSION, 1, &secbufPointer2 };

			initSecurity = SECUR32$InitializeSecurityContextW(
				&hCredential,
				&newContext, //pass cred handle
				(SEC_WCHAR*)spn,
				ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE,
				0,
				SECURITY_NATIVE_DREP,
				&input, //pass Sec Buffer
				0,
				&newContext,
				&output2,
				&contextAttr,
				&expiry);

			ticket = output2.pBuffers;
			//BeaconPrintf(CALLBACK_OUTPUT, "[-] size : %d\n", (DWORD)ticket->cbBuffer);

			if (ticket->pvBuffer == NULL) {
				BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW failed: %S\n", initSecurity);
				return FALSE;
			}
		}

		struct berval cred;
		cred.bv_len = ticket->cbBuffer;
		cred.bv_val = (char*)ticket->pvBuffer;

		//connect
		WLDAP32$ldap_sasl_bind_sW(
			pLdapConnection, // Session Handle
			L"",    // Domain DN
			L"GSSAPI", //auth type
			&cred, //auth
			NULL, //ctrl
			NULL,  //ctrl
			&servresp); // response
		WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_ERROR_NUMBER, &res);

		// take token from ldap_sasl_bind_sW
		if(servresp->bv_val != NULL){
			output.pBuffers->cbBuffer = servresp->bv_len;
			output.pBuffers->pvBuffer = servresp->bv_val;
		}else{
			BeaconPrintf(CALLBACK_ERROR, "[-] no token back from ldap_sasl_bind_sW");
			return FALSE;
		}

		//BeaconPrintf(CALLBACK_OUTPUT, "ldap_sasl_bind: %D", result);
		//BeaconPrintf(CALLBACK_OUTPUT, "LDAP_OPT_ERROR_NUMBER: %d\n", res);

		if(ssl == TRUE){
			if (res == LDAP_INVALID_CREDENTIALS)
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[-] LDAPS://%S REQUIRES channel binding (LDAP_INVALID_CREDENTIALS)\n", dc ? dc : L"target");
				WLDAP32$ldap_unbind_s(pLdapConnection);
				return TRUE;
			}
			else if (res == LDAP_SUCCESS)
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAPS://%S does NOT require channel binding (bind succeeded)\n", dc ? dc : L"target");
				WLDAP32$ldap_unbind_s(pLdapConnection);
				return FALSE;
			}
			else if (res == LDAP_SASL_BIND_IN_PROGRESS)
			{
				continue;
			}
			else{
				BeaconPrintf(CALLBACK_ERROR, "[-] LDAPS unknown issue (error: %lu)\n", res);
				return FALSE;
			}
		}else{
			if (res == LDAP_STRONG_AUTH_REQUIRED)
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[-] LDAP://%S REQUIRES signing\n", dc ? dc : L"target");
				WLDAP32$ldap_unbind_s(pLdapConnection);
				return TRUE;
			}
			else if (res == LDAP_SUCCESS)
			{
				BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAP://%S does NOT require signing\n", dc ? dc : L"target");
				WLDAP32$ldap_unbind_s(pLdapConnection);
				return FALSE;
			}
			else if (res == LDAP_SASL_BIND_IN_PROGRESS)
			{
				continue;
			}
			else{
				BeaconPrintf(CALLBACK_ERROR, "[-] LDAP unknown issue (error: %lu)\n", res);
				return FALSE;
			}
		}

	} while (res == LDAP_SASL_BIND_IN_PROGRESS);

	return TRUE;
}

void go(char* args, int len)
{
	datap parser;
	PDOMAIN_CONTROLLER_INFOA pdcInfo = NULL;
	DWORD dwRet = 0;

	BeaconDataParse(&parser, args, len);

	wchar_t* targetDC = NULL;

	// Extract DC argument if provided
	if (len > 0) {
		targetDC = (wchar_t*)BeaconDataExtract(&parser, NULL);
	}

	wchar_t finalDC[256] = {0};
	wchar_t finalSPN[256] = {0};

	// Auto-discover DC if not provided
	if (!targetDC || targetDC[0] == L'\0') {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] No DC specified, attempting auto-discovery...\n");

		dwRet = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);
		if (dwRet == ERROR_SUCCESS && pdcInfo) {
			// Skip the "\\" prefix from DomainControllerName
			char* dcName = pdcInfo->DomainControllerName + 2;
			MSVCRT$swprintf_s(finalDC, 256, L"%hs", dcName);
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Auto-discovered DC: %S\n", finalDC);
		} else {
			BeaconPrintf(CALLBACK_ERROR, "[-] Failed to auto-discover DC (error: %d)\n", dwRet);
			BeaconPrintf(CALLBACK_ERROR, "[-] Please specify DC manually: ldapsecuritycheck <DC>\n");
			goto cleanup;
		}
	} else {
		MSVCRT$wcscpy(finalDC, targetDC);
	}

	// Always auto-generate SPN from DC
	MSVCRT$wcscpy(finalSPN, L"ldap/");
	MSVCRT$wcscat(finalSPN, finalDC);

	BeaconPrintf(CALLBACK_OUTPUT,"[+] Target DC: %S\n", finalDC);
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Target SPN: %S\n", finalSPN);

	KERNEL32$LoadLibraryA("WLDAP32");

	BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Testing LDAP signing requirements...\n");
	checkLDAP(finalDC, finalSPN, FALSE);

	BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Testing LDAPS channel binding requirements...\n");
	checkLDAP(finalDC, finalSPN, TRUE);

cleanup:
	// Free the DC info buffer if allocated
	if (pdcInfo) {
		NETAPI32$NetApiBufferFree(pdcInfo);
	}
}
