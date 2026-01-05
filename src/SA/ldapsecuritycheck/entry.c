
#include <windows.h>
#include "beacon.h"
#include "../../common/bofdefs.h"

VERIFYSERVERCERT ServerCertCallback;
BOOLEAN _cdecl ServerCertCallback(PLDAP Connection, PCCERT_CONTEXT pServerCert) {
	return TRUE;
}

BOOL checkLDAP(wchar_t* dc, wchar_t* spn, BOOL ssl) {
	// Track what needs cleanup
	CredHandle hCredential;
	BOOL credHandleAcquired = FALSE;
	BOOL contextInitialized = FALSE;
	LDAP* pLdapConnection = NULL;
	struct berval* servresp = NULL;
	SecBuffer secbufPointer = { 0, SECBUFFER_TOKEN, NULL };
	SecBufferDesc output = { SECBUFFER_VERSION, 1, &secbufPointer };
	SecBuffer secbufPointer2 = { 0, SECBUFFER_TOKEN, NULL };  // Fixed: separate buffer for output2
	SecBufferDesc output2 = { SECBUFFER_VERSION, 1, &secbufPointer2 };  // Fixed: points to secbufPointer2
	CtxtHandle newContext;
	BOOL retVal = FALSE;

	// Acquire credentials handle
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

	if (getHandle != SEC_E_OK) {
		BeaconPrintf(CALLBACK_ERROR, "[-] AcquireCredentialsHandleW failed: %d\n", getHandle);  // Fixed: %d instead of %lu
		return FALSE;
	}
	credHandleAcquired = TRUE;  // Mark for cleanup

	// Initialize LDAP connection
	ULONG result;
	if (ssl == TRUE) {
		pLdapConnection = WLDAP32$ldap_initW(dc, 636);
	}
	else {
		pLdapConnection = WLDAP32$ldap_initW(dc, 389);
	}

	if (pLdapConnection == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "[-] Failed to establish LDAP connection");
		goto cleanup;  // Fixed: use goto instead of return
	}

	const int version = LDAP_VERSION3;
	result = WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_VERSION, (void*)&version);

	if (ssl == TRUE) {
		WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_SSL, &result);
		if (result == 0)
			WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SSL, LDAP_OPT_ON);

		WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_SIGN, &result);
		if (result == 0)
			WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SIGN, LDAP_OPT_ON);

		WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_ENCRYPT, &result);
		if (result == 0)
			WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_ENCRYPT, LDAP_OPT_ON);

		WLDAP32$ldap_set_optionW(pLdapConnection, LDAP_OPT_SERVER_CERTIFICATE, (void*)&ServerCertCallback);
	}

	result = WLDAP32$ldap_connect(pLdapConnection, NULL);
	if (result != LDAP_SUCCESS) {
		BeaconPrintf(CALLBACK_ERROR, "[-] ldap_connect failed: %lu", result);
		goto cleanup;  // Fixed: use goto instead of return
	}

	ULONG res;
	SECURITY_STATUS initSecurity;
	ULONG contextAttr;
	TimeStamp expiry;
	PSecBuffer ticket;
	int count = 0;

	// Main authentication loop
	do {
		if (count > 5) {
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

			// Fixed: Check return value for errors
			if (initSecurity != SEC_E_OK &&
				initSecurity != SEC_I_CONTINUE_NEEDED &&
				initSecurity != SEC_I_COMPLETE_NEEDED &&
				initSecurity != SEC_I_COMPLETE_AND_CONTINUE) {
				BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW failed: 0x%08x\n", initSecurity);
				goto cleanup;
			}

			ticket = output.pBuffers;

			// Fixed: Check ticket is not NULL before dereferencing
			if (ticket == NULL || ticket->pvBuffer == NULL) {
				BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW returned no token: %d\n", initSecurity);  // Fixed: %d
				goto cleanup;
			}
			contextInitialized = TRUE;  // Mark for cleanup
		}
		else {
			SecBuffer serverResponseToken = { servresp->bv_len, SECBUFFER_TOKEN, servresp->bv_val };
			SecBufferDesc input = { SECBUFFER_VERSION, 1, &serverResponseToken };

			initSecurity = SECUR32$InitializeSecurityContextW(
				&hCredential,
				&newContext,
				(SEC_WCHAR*)spn,
				ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE,
				0,
				SECURITY_NATIVE_DREP,
				&input,
				0,
				&newContext,
				&output2,
				&contextAttr,
				&expiry);

			// Fixed: Check return value for errors
			if (initSecurity != SEC_E_OK &&
				initSecurity != SEC_I_CONTINUE_NEEDED &&
				initSecurity != SEC_I_COMPLETE_NEEDED &&
				initSecurity != SEC_I_COMPLETE_AND_CONTINUE) {
				BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW failed: 0x%08x\n", initSecurity);
				goto cleanup;
			}

			ticket = output2.pBuffers;

			// Fixed: Check ticket is not NULL before dereferencing
			if (ticket == NULL || ticket->pvBuffer == NULL) {
				BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW returned no token: %d\n", initSecurity);  // Fixed: %d
				goto cleanup;
			}
		}

		struct berval cred;
		cred.bv_len = ticket->cbBuffer;
		cred.bv_val = (char*)ticket->pvBuffer;

		// Perform SASL bind
		WLDAP32$ldap_sasl_bind_sW(
			pLdapConnection,
			L"",
			L"GSSAPI",
			&cred,
			NULL,
			NULL,
			&servresp);
		WLDAP32$ldap_get_optionW(pLdapConnection, LDAP_OPT_ERROR_NUMBER, &res);

		// Check for response token
		if (servresp == NULL || servresp->bv_val == NULL) {
			BeaconPrintf(CALLBACK_ERROR, "[-] no token back from ldap_sasl_bind_sW");
			goto cleanup;
		}

		// Check results based on connection type
		if (ssl == TRUE) {
			if (res == LDAP_INVALID_CREDENTIALS) {
				BeaconPrintf(CALLBACK_OUTPUT, "[-] LDAPS://%S REQUIRES channel binding (LDAP_INVALID_CREDENTIALS)\n", dc ? dc : L"target");
				retVal = TRUE;
				goto cleanup;
			}
			else if (res == LDAP_SUCCESS) {
				BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAPS://%S does NOT require channel binding (bind succeeded)\n", dc ? dc : L"target");
				retVal = FALSE;
				goto cleanup;
			}
			else if (res == LDAP_SASL_BIND_IN_PROGRESS) {
				continue;
			}
			else {
				BeaconPrintf(CALLBACK_ERROR, "[-] LDAPS unknown issue (error: %lu)\n", res);
				goto cleanup;
			}
		}
		else {
			if (res == LDAP_STRONG_AUTH_REQUIRED) {
				BeaconPrintf(CALLBACK_OUTPUT, "[-] LDAP://%S REQUIRES signing\n", dc ? dc : L"target");
				retVal = TRUE;
				goto cleanup;
			}
			else if (res == LDAP_SUCCESS) {
				BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAP://%S does NOT require signing\n", dc ? dc : L"target");
				retVal = FALSE;
				goto cleanup;
			}
			else if (res == LDAP_SASL_BIND_IN_PROGRESS) {
				continue;
			}
			else {
				BeaconPrintf(CALLBACK_ERROR, "[-] LDAP unknown issue (error: %lu)\n", res);
				goto cleanup;
			}
		}

	} while (res == LDAP_SASL_BIND_IN_PROGRESS);

	retVal = TRUE;

cleanup:
	// Fixed: Free servresp if allocated
	if (servresp) {
		WLDAP32$ber_bvfree(servresp);
	}

	// Fixed: Delete security context if initialized
	if (contextInitialized) {
		SECUR32$DeleteSecurityContext(&newContext);
	}

	// Fixed: Free buffers allocated by InitializeSecurityContextW
	if (output.pBuffers && output.pBuffers->pvBuffer) {
		SECUR32$FreeContextBuffer(output.pBuffers->pvBuffer);
	}
	if (output2.pBuffers && output2.pBuffers->pvBuffer) {
		SECUR32$FreeContextBuffer(output2.pBuffers->pvBuffer);
	}

	// Fixed: Unbind LDAP connection
	if (pLdapConnection) {
		WLDAP32$ldap_unbind_s(pLdapConnection);
	}

	// Fixed: Free credentials handle
	if (credHandleAcquired) {
		SECUR32$FreeCredentialsHandle(&hCredential);
	}

	return retVal;
}

void go(char* args, int len) {
	datap parser;
	PDOMAIN_CONTROLLER_INFOA pdcInfo = NULL;
	DWORD dwRet = 0;

	BeaconDataParse(&parser, args, len);

	wchar_t* targetDC = NULL;

	if (len > 0) {
		targetDC = (wchar_t*)BeaconDataExtract(&parser, NULL);
	}

	wchar_t finalDC[256] = { 0 };
	wchar_t finalSPN[256] = { 0 };

	if (!targetDC || targetDC[0] == L'\0') {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] No DC specified, attempting auto-discovery...\n");

		dwRet = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);
		if (dwRet == ERROR_SUCCESS && pdcInfo) {
			char* dcName = pdcInfo->DomainControllerName;
			if (dcName && dcName[0] == '\\' && dcName[1] == '\\') {
				dcName += 2;
			}
			MSVCRT$swprintf_s(finalDC, 256, L"%hs", dcName);
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Auto-discovered DC: %S\n", finalDC);
		}
		else {
			BeaconPrintf(CALLBACK_ERROR, "[-] Failed to auto-discover DC (error: %d)\n", dwRet);
			BeaconPrintf(CALLBACK_ERROR, "[-] Please specify DC manually: ldapsecuritycheck <DC>\n");
			goto cleanup;
		}
	}
	else {
		MSVCRT$wcsncpy(finalDC, targetDC, 255);
		finalDC[255] = L'\0';
	}

	MSVCRT$_snwprintf(finalSPN, 256, L"ldap/%s", finalDC);
	finalSPN[255] = L'\0';

	BeaconPrintf(CALLBACK_OUTPUT, "[+] Target DC: %S\n", finalDC);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Target SPN: %S\n", finalSPN);

	BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Testing LDAP signing requirements...\n");
	checkLDAP(finalDC, finalSPN, FALSE);

	BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Testing LDAPS channel binding requirements...\n");
	checkLDAP(finalDC, finalSPN, TRUE);

cleanup:
	if (pdcInfo) {
		NETAPI32$NetApiBufferFree(pdcInfo);
	}
}